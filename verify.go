package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
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

// verifyChain checks the certificates the server sent against the trusted
// roots (the system store unless a test injected its own pool). It returns
// nil when the chain is trusted, or the reasons it is not.
func (c *Checker) verifyChain(ctx context.Context, certs []*x509.Certificate, now time.Time) []string {
	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, ic := range certs[1:] {
		intermediates.AddCert(ic)
	}
	opts := x509.VerifyOptions{
		Roots:         c.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	_, err := leaf.Verify(opts)
	if err == nil {
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
		if _, err = leaf.Verify(opts); err == nil {
			return reasons
		}
	}
	return append(reasons, c.classify(ctx, leaf, opts, err))
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
		if _, verr := leaf.Verify(opts); verr == nil {
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
// http and https links and gives up quietly on any error.
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
