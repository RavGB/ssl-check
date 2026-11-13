package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"syscall"
	"time"
)

// Short reasons for an untrusted chain. They appear in the JSON output.
const (
	reasonExpired             = "expired"
	reasonNotYetValid         = "not yet valid"
	reasonSelfSigned          = "self-signed"
	reasonUnknownAuthority    = "unknown authority"
	reasonMissingIntermediate = "missing intermediate"
	reasonChainExpired        = "expired intermediate"
	reasonWeakSignature       = "weak signature"
	reasonOtherPrefix         = "not trusted: "
)

// Largest intermediate certificate download we accept.
const maxIssuerDownload = 1 << 20

// verifyFunc verifies a leaf certificate and returns the chains it found.
type verifyFunc func(leaf *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error)

// verifyChain checks the certificates the server sent against the trusted
// roots (the system store unless a test injected its own pool). It returns
// nil when the chain is trusted, or the reasons it is not.
func (c *Checker) verifyChain(ctx context.Context, certs []*x509.Certificate, now time.Time) []string {
	leaf, sent := certs[0], certs[1:]
	intermediates := x509.NewCertPool()
	for _, ic := range sent {
		intermediates.AddCert(ic)
	}
	opts := x509.VerifyOptions{
		Roots:         c.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	chains, err := c.verify(leaf, opts)
	if err == nil {
		if !sentWholeChain(chains, sent) {
			return []string{reasonMissingIntermediate}
		}
		return nil
	}

	var reasons []string
	switch {
	case now.After(leaf.NotAfter):
		reasons = append(reasons, reasonExpired)
	case now.Before(leaf.NotBefore):
		reasons = append(reasons, reasonNotYetValid)
	}
	if len(reasons) > 0 {
		// The dates alone make verification fail. Try again at a moment when
		// the certificate was valid, to find out if anything else is wrong.
		opts.CurrentTime = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
		if chains, err = c.verify(leaf, opts); err == nil {
			if !sentWholeChain(chains, sent) {
				reasons = append(reasons, reasonMissingIntermediate)
			}
			return reasons
		}
	}
	return append(reasons, c.classify(ctx, leaf, opts, err))
}

// sentWholeChain reports whether at least one verified chain is made only of
// certificates the server sent, plus the trusted root at the end.
//
// A successful verification is not enough on its own. On macOS and Windows,
// Go hands verification to the operating system, which fills in a missing
// intermediate by itself (from its cache or by downloading it). Many phones,
// apps and tools do not, so a server that leaves out its intermediate still
// has a problem. An intermediate counts as sent when the server sent a
// certificate with the same name and key, so a reissued copy of the same
// intermediate is fine.
func sentWholeChain(chains [][]*x509.Certificate, sent []*x509.Certificate) bool {
	if len(chains) == 0 {
		return true // nothing to compare; Verify always returns a chain on success
	}
	for _, chain := range chains {
		if len(chain) <= 2 {
			return true // the leaf itself, or the leaf and the root that signed it
		}
		complete := true
		for _, ic := range chain[1 : len(chain)-1] {
			if !slices.ContainsFunc(sent, func(s *x509.Certificate) bool { return sameNameAndKey(s, ic) }) {
				complete = false
				break
			}
		}
		if complete {
			return true
		}
	}
	return false
}

func sameNameAndKey(a, b *x509.Certificate) bool {
	return bytes.Equal(a.RawSubject, b.RawSubject) &&
		bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo)
}

// classify explains why a certificate whose own dates are fine is not trusted.
func (c *Checker) classify(ctx context.Context, leaf *x509.Certificate, opts x509.VerifyOptions, err error) string {
	if isSelfSigned(leaf) {
		return reasonSelfSigned
	}
	if weakSignature(leaf.SignatureAlgorithm) {
		return reasonWeakSignature
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return reasonChainExpired
	}
	// Many servers forget to send the intermediate certificate. The leaf
	// usually says where to download it. If the chain is trusted once we add
	// it, the intermediate is what is missing.
	if extra := c.fetchIssuers(ctx, leaf); len(extra) > 0 {
		for _, ic := range extra {
			opts.Intermediates.AddCert(ic)
		}
		if _, verr := c.verify(leaf, opts); verr == nil {
			return reasonMissingIntermediate
		}
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return reasonUnknownAuthority
	}
	return reasonOtherPrefix + err.Error()
}

func isSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func weakSignature(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// fetchIssuers downloads the issuer certificate from the address listed in
// the leaf (the "Authority Information Access" field). It only follows
// http and https links to public addresses and gives up quietly on any
// error.
func (c *Checker) fetchIssuers(ctx context.Context, leaf *x509.Certificate) []*x509.Certificate {
	for i, raw := range leaf.IssuingCertificateURL {
		if i == 2 {
			break
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if certs := c.download(ctx, u.String()); len(certs) > 0 {
			return certs
		}
	}
	return nil
}

func (c *Checker) download(ctx context.Context, link string) []*x509.Certificate {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIssuerDownload))
	if err != nil {
		return nil
	}
	return parseCertificates(body)
}

// parseCertificates reads DER (one or more certificates back to back) or PEM.
func parseCertificates(b []byte) []*x509.Certificate {
	if certs, err := x509.ParseCertificates(b); err == nil && len(certs) > 0 {
		return certs
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
}

// sharedAddressSpace (100.64.0.0/10) is used inside carrier and cloud
// networks and cannot be reached from the internet.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// isPublic reports whether ip is an ordinary internet address.
func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !sharedAddressSpace.Contains(ip)
}

// publicAddressOnly is the Control function of the dialer used for the
// intermediate download. It runs after the name has been looked up, for
// every connection including redirects, and refuses any address that is
// not public: loopback, private networks, link-local (such as the cloud
// metadata address 169.254.169.254) and so on. The link comes from the
// certificate of the site being checked, so the site decides where it
// points, and it must not be able to reach inside the network the tool
// runs in.
func publicAddressOnly(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("refusing to connect to %q: %w", address, err)
	}
	if !isPublic(ap.Addr()) {
		return fmt.Errorf("refusing to connect to %s: not a public address", ap.Addr())
	}
	return nil
}
