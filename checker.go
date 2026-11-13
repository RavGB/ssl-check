package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

const (
	toolName    = "ssl-check"
	toolVersion = "0.1"
	userAgent   = "RavGB-ssl-check/0.1 (+https://ravgb.com)"
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Checker runs the checks for one site at a time. One Checker is shared by
// all goroutines; it is never modified after newChecker returns.
type Checker struct {
	warn    time.Duration
	timeout time.Duration
	roots   *x509.CertPool // nil means the trust store of this computer
	now     func() time.Time
	dial    dialFunc
	client  *http.Client // only used to download a missing intermediate
}

// Option changes how a Checker works. Tests use them to inject a private
// root certificate and a fake network.
type Option func(*Checker)

// withRoots trusts only the given root certificates instead of the system ones.
func withRoots(pool *x509.CertPool) Option { return func(c *Checker) { c.roots = pool } }

// withDialer replaces the function used to open network connections.
func withDialer(d dialFunc) Option { return func(c *Checker) { c.dial = d } }

func newChecker(warnDays int, timeout time.Duration, opts ...Option) *Checker {
	var d net.Dialer
	c := &Checker{
		warn:    time.Duration(warnDays) * 24 * time.Hour,
		timeout: timeout,
		now:     time.Now,
		dial:    d.DialContext,
	}
	for _, o := range opts {
		o(c)
	}
	c.client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           c.dial,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	return c
}

// CheckAll checks every target, at most concurrency at a time, and returns
// the results in the same order as targets.
func (c *Checker) CheckAll(ctx context.Context, targets []Target, concurrency int) []Result {
	results := make([]Result, len(targets))
	for i, t := range targets {
		// Placeholder for sites that never start because the run was stopped.
		results[i] = stoppedResult(t)
	}
	forEach(ctx, len(targets), concurrency, func(ctx context.Context, i int) {
		results[i] = c.Check(ctx, targets[i]) // each goroutine writes only its own slot
	})
	return results
}

// Check connects to one site and inspects its certificate and TLS settings.
func (c *Checker) Check(ctx context.Context, t Target) Result {
	state, err := c.handshake(ctx, t, legacyFriendlyConfig(t.Host))
	if err != nil {
		if ctx.Err() != nil {
			return stoppedResult(t)
		}
		return failedResult(t, c.explainConnError(t, err))
	}
	if len(state.PeerCertificates) == 0 {
		return failedResult(t, "the server did not send a certificate")
	}

	now := c.now()
	certs := state.PeerCertificates
	leaf := certs[0]

	info := describeCert(leaf, now)
	info.ChainSent = len(certs)
	info.NameMatches = leaf.VerifyHostname(t.Host) == nil
	info.UntrustedReasons = c.verifyChain(ctx, certs, now)
	info.Trusted = len(info.UntrustedReasons) == 0

	r := Result{
		Site:        t.Label(),
		Input:       t.Input,
		Host:        t.Host,
		Port:        t.Port,
		Certificate: &info,
		TLSVersion:  tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		TLS10:       c.probe(ctx, t, tls.VersionTLS10),
		TLS11:       c.probe(ctx, t, tls.VersionTLS11),
	}
	assess(&r, state.Version, state.CipherSuite, c.warn, now)
	return r
}

// allCipherSuites lists every suite Go implements, old ones included, so an
// old server can still be inspected. Go orders them by its own preference,
// so modern suites are still offered first.
var allCipherSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}()

// legacyFriendlyConfig accepts any certificate and any TLS version from 1.0
// up. That is deliberate: this tool has to see broken or outdated setups to
// report on them. Trust and the name are checked afterwards in verifyChain
// and VerifyHostname, and nothing is ever sent over these connections.
func legacyFriendlyConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // verified by hand in verifyChain
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuites,
	}
}

type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

type handshakeError struct {
	err      error
	timedOut bool
}

func (e *handshakeError) Error() string { return e.err.Error() }
func (e *handshakeError) Unwrap() error { return e.err }

// handshake opens a TCP connection, completes a TLS handshake, and closes it.
func (c *Checker) handshake(ctx context.Context, t Target, cfg *tls.Config) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	raw, err := c.dial(ctx, "tcp", t.Addr())
	if err != nil {
		return tls.ConnectionState{}, &connectError{err}
	}
	conn := tls.Client(raw, cfg)
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, &handshakeError{err: err, timedOut: ctx.Err() != nil}
	}
	return conn.ConnectionState(), nil
}

// Probe says whether a server still accepts one old TLS version.
type Probe string

const (
	probeAccepted Probe = "accepted"
	probeRefused  Probe = "refused"
	probeUnknown  Probe = "unknown"
)

// probe makes a separate connection that only allows one TLS version.
func (c *Checker) probe(ctx context.Context, t Target, version uint16) Probe {
	cfg := legacyFriendlyConfig(t.Host)
	cfg.MinVersion, cfg.MaxVersion = version, version
	_, err := c.handshake(ctx, t, cfg)
	var he *handshakeError
	switch {
	case err == nil:
		return probeAccepted
	case errors.As(err, &he) && !he.timedOut:
		// We reached the server and it turned the version down.
		return probeRefused
	default:
		return probeUnknown
	}
}

// explainConnError turns a network error into a short plain sentence.
func (c *Checker) explainConnError(t Target, err error) string {
	var (
		dnsErr *net.DNSError
		he     *handshakeError
	)
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return fmt.Sprintf("the name %s does not exist in DNS", t.Host)
	case errors.As(err, &dnsErr):
		return fmt.Sprintf("the DNS lookup for %s failed (%s)", t.Host, dnsErr.Err)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("nothing accepted the connection on port %s", t.Port)
	case errors.As(err, &he) && he.timedOut:
		return fmt.Sprintf("the server did not finish the secure handshake within %s", c.timeout)
	case isTimeout(err):
		return fmt.Sprintf("no answer on port %s within %s", t.Port, c.timeout)
	case errors.As(err, &he):
		return fmt.Sprintf("the secure handshake failed (%v)", he.err)
	default:
		return fmt.Sprintf("could not connect (%v)", err)
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
