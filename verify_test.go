package main

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// osLikeVerifier behaves like the verifiers of macOS and Windows: when the
// server left out an intermediate, they find it on their own (from a cache
// or by downloading it) and still report the chain as trusted.
func osLikeVerifier(cache ...*x509.Certificate) verifyFunc {
	return func(leaf *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
		pool := x509.NewCertPool()
		if opts.Intermediates != nil {
			pool = opts.Intermediates.Clone()
		}
		for _, c := range cache {
			pool.AddCert(c)
		}
		opts.Intermediates = pool
		return leaf.Verify(opts)
	}
}

func TestSentWholeChain(t *testing.T) {
	now := time.Now()
	root := newRootCA(t, "Root")
	inter := newIntermediate(t, root, "Inter")
	inter2 := newIntermediate(t, inter, "Inter 2")
	leaf, _ := newLeaf(t, inter, leafSpec{names: []string{"a.test"}, notBefore: now, notAfter: now.Add(days(90))})
	deepLeaf, _ := newLeaf(t, inter2, leafSpec{names: []string{"b.test"}, notBefore: now, notAfter: now.Add(days(90))})
	direct, _ := newLeaf(t, root, leafSpec{names: []string{"c.test"}, notBefore: now, notAfter: now.Add(days(90))})

	// The same intermediate issued again: same name and key, new serial.
	tmpl := caTemplate("Inter")
	reissued := sign(t, tmpl, root.cert, &inter.key.PublicKey, root.key)

	full := []*x509.Certificate{leaf, inter.cert, root.cert}
	deep := []*x509.Certificate{deepLeaf, inter2.cert, inter.cert, root.cert}
	for _, tc := range []struct {
		name   string
		chains [][]*x509.Certificate
		sent   []*x509.Certificate
		want   bool
	}{
		{"intermediate sent", [][]*x509.Certificate{full}, []*x509.Certificate{inter.cert}, true},
		{"intermediate not sent", [][]*x509.Certificate{full}, nil, false},
		{"only an unrelated certificate sent", [][]*x509.Certificate{full}, []*x509.Certificate{inter2.cert}, false},
		{"reissued copy of the intermediate sent", [][]*x509.Certificate{full}, []*x509.Certificate{reissued}, true},
		{"root sent but not the intermediate", [][]*x509.Certificate{full}, []*x509.Certificate{root.cert}, false},
		{"leaf signed by the root", [][]*x509.Certificate{{direct, root.cert}}, nil, true},
		{"second intermediate missing", [][]*x509.Certificate{deep}, []*x509.Certificate{inter2.cert}, false},
		{"both intermediates sent", [][]*x509.Certificate{deep}, []*x509.Certificate{inter2.cert, inter.cert}, true},
		{"one of two chains complete", [][]*x509.Certificate{full, {leaf, reissued, root.cert}}, []*x509.Certificate{reissued}, true},
		{"leaf is itself trusted", [][]*x509.Certificate{{leaf}}, nil, true},
	} {
		if got := sentWholeChain(tc.chains, tc.sent); got != tc.want {
			t.Errorf("%s: sentWholeChain = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// On macOS and Windows the system verifier fills in a missing intermediate
// by itself. The tool must still notice that the server did not send it.
func TestMissingIntermediateWhenSystemFillsTheGap(t *testing.T) {
	l := buildFullLab(t)
	now := time.Now()
	leaf, key := newLeaf(t, l.inter, leafSpec{names: []string{"expiredmissing.test"}, notBefore: now.Add(-days(100)), notAfter: now.Add(-days(2)), issuerURL: l.aiaAddress})
	l.site(t, "expiredmissing.test", chainFor(leaf, key), nil)

	for _, tc := range []struct {
		host    string
		codes   []string
		trusted bool
		reasons []string
	}{
		{"valid.test", nil, true, nil},
		{"missingint.test", []string{codeMissingIntermediate}, false, []string{reasonMissingIntermediate}},
		{"expiredmissing.test", []string{codeExpired, codeMissingIntermediate}, false, []string{reasonExpired, reasonMissingIntermediate}},
		{"unknownca.test", []string{codeUnknownAuthority}, false, []string{reasonUnknownAuthority}},
	} {
		for _, v := range []struct {
			name string
			opts []Option
		}{
			{"Go verifier", nil},
			{"system-like verifier", []Option{withVerifier(osLikeVerifier(l.inter.cert))}},
		} {
			t.Run(tc.host+" with "+v.name, func(t *testing.T) {
				c := newChecker(30, 5*time.Second, append(l.options(), v.opts...)...)
				r := c.Check(context.Background(), mustTarget(t, tc.host))
				if r.Certificate == nil {
					t.Fatalf("no certificate details; error: %s", r.Error)
				}
				if got := codesOf(r); !slices.Equal(got, tc.codes) {
					t.Errorf("finding codes = %v, want %v", got, tc.codes)
				}
				if r.Certificate.Trusted != tc.trusted {
					t.Errorf("trusted = %v, want %v", r.Certificate.Trusted, tc.trusted)
				}
				if !slices.Equal(r.Certificate.UntrustedReasons, tc.reasons) {
					t.Errorf("untrusted reasons = %q, want %q", r.Certificate.UntrustedReasons, tc.reasons)
				}
			})
		}
	}
}

func TestPublicAddressOnly(t *testing.T) {
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"93.184.215.14:80", true},
		{"[2606:4700::6810:84e5]:443", true},
		{"127.0.0.1:80", false},
		{"[::1]:80", false},
		{"10.1.2.3:80", false},
		{"172.16.0.1:80", false},
		{"192.168.1.1:80", false},
		{"169.254.169.254:80", false},
		{"[fd00:ec2::254]:80", false},
		{"[fe80::1]:80", false},
		{"100.64.0.1:80", false},
		{"0.0.0.0:80", false},
		{"[::]:80", false},
		{"224.0.0.1:80", false},
		{"[::ffff:127.0.0.1]:80", false},
		{"[::ffff:169.254.169.254]:80", false},
		{"not an address", false},
	} {
		err := publicAddressOnly("tcp", tc.addr, nil)
		if (err == nil) != tc.ok {
			t.Errorf("publicAddressOnly(%q) = %v, want allowed=%v", tc.addr, err, tc.ok)
		}
	}
	if !isPublic(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 should count as public")
	}
}

// Without a test dialer, the intermediate download must refuse addresses
// inside the network the tool runs in, such as 127.0.0.1 or the cloud
// metadata address.
func TestIntermediateDownloadSkipsPrivateAddresses(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := newChecker(30, 2*time.Second)
	if certs := c.download(context.Background(), srv.URL+"/intermediate.cer"); certs != nil {
		t.Errorf("download returned %d certificates, want none", len(certs))
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the local server was contacted %d times, want 0", n)
	}
}
