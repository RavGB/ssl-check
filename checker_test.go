package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// lab is a set of local HTTPS servers, each pretending to be a named site,
// all signed by a private root that only the checker under test trusts.
type lab struct {
	root  *testCA
	inter *testCA
	roots *x509.CertPool
	net   fakeNet

	mu         sync.Mutex
	aiaAgents  []string // User-Agent of each intermediate download
	aiaAddress string
}

func newLab(t *testing.T) *lab {
	t.Helper()
	l := &lab{net: fakeNet{}}
	l.root = newRootCA(t, "Test Root")
	l.inter = newIntermediate(t, l.root, "Test Intermediate")
	l.roots = x509.NewCertPool()
	l.roots.AddCert(l.root.cert)

	// Serves the intermediate, like a real authority's download address.
	aia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.aiaAgents = append(l.aiaAgents, r.Header.Get("User-Agent"))
		l.mu.Unlock()
		if r.URL.Path != "/intermediate.cer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Write(l.inter.cert.Raw)
	}))
	t.Cleanup(aia.Close)
	l.aiaAddress = aia.URL + "/intermediate.cer"
	return l
}

// site starts a server for host:443.
func (l *lab) site(t *testing.T, host string, cert tls.Certificate, tune func(*tls.Config)) {
	t.Helper()
	l.net[host+":443"] = startTLS(t, cert, tune)
}

// goodCert is a normal certificate for names, signed by the intermediate,
// with the intermediate sent along as it should be.
func (l *lab) goodCert(t *testing.T, names ...string) tls.Certificate {
	now := time.Now()
	leaf, key := newLeaf(t, l.inter, leafSpec{names: names, notBefore: now.Add(-days(10)), notAfter: now.Add(days(200.2))})
	return chainFor(leaf, key, l.inter.cert)
}

func (l *lab) checker(warnDays int, timeout time.Duration) *Checker {
	return newChecker(warnDays, timeout, withRoots(l.roots), withDialer(l.net.dial))
}

func (l *lab) options() []Option {
	return []Option{withRoots(l.roots), withDialer(l.net.dial)}
}

// buildFullLab creates one site for every situation the tool must recognise.
func buildFullLab(t *testing.T) *lab {
	t.Helper()
	l := newLab(t)
	now := time.Now()

	l.site(t, "valid.test", l.goodCert(t, "valid.test", "www.valid.test"), nil)

	leaf, key := newLeaf(t, l.inter, leafSpec{names: []string{"expired.test"}, notBefore: now.Add(-days(100)), notAfter: now.Add(-days(3.2))})
	l.site(t, "expired.test", chainFor(leaf, key, l.inter.cert), nil)

	leaf, key = newLeaf(t, l.inter, leafSpec{names: []string{"soon.test"}, notBefore: now.Add(-days(80)), notAfter: now.Add(days(10.2))})
	l.site(t, "soon.test", chainFor(leaf, key, l.inter.cert), nil)

	l.site(t, "wrongname.test", l.goodCert(t, "other.test"), nil)

	leaf, key = newLeaf(t, nil, leafSpec{names: []string{"selfsigned.test"}, notBefore: now.Add(-days(1)), notAfter: now.Add(days(300))})
	l.site(t, "selfsigned.test", chainFor(leaf, key), nil)

	leaf, key = newLeaf(t, l.inter, leafSpec{names: []string{"notyet.test"}, notBefore: now.Add(days(2)), notAfter: now.Add(days(100))})
	l.site(t, "notyet.test", chainFor(leaf, key, l.inter.cert), nil)

	l.site(t, "oldtls.test", l.goodCert(t, "oldtls.test"), func(c *tls.Config) {
		c.MinVersion = tls.VersionTLS10
	})

	l.site(t, "legacy.test", l.goodCert(t, "legacy.test"), func(c *tls.Config) {
		c.MinVersion = tls.VersionTLS10
		c.MaxVersion = tls.VersionTLS11
	})

	l.site(t, "weakcipher.test", l.goodCert(t, "weakcipher.test"), func(c *tls.Config) {
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}
	})

	// Signed by the intermediate, but the server forgets to send it.
	leaf, key = newLeaf(t, l.inter, leafSpec{names: []string{"missingint.test"}, notBefore: now.Add(-days(1)), notAfter: now.Add(days(90)), issuerURL: l.aiaAddress})
	l.site(t, "missingint.test", chainFor(leaf, key), nil)

	// Signed by a root nobody trusts.
	stranger := newRootCA(t, "Stranger Root")
	leaf, key = newLeaf(t, stranger, leafSpec{names: []string{"unknownca.test"}, notBefore: now.Add(-days(1)), notAfter: now.Add(days(90))})
	l.site(t, "unknownca.test", chainFor(leaf, key), nil)

	// Self-signed and expired: both problems should be reported.
	leaf, key = newLeaf(t, nil, leafSpec{names: []string{"expiredself.test"}, notBefore: now.Add(-days(400)), notAfter: now.Add(-days(30))})
	l.site(t, "expiredself.test", chainFor(leaf, key), nil)

	// Nothing listens here.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.net["down.test:443"] = ln.Addr().String()
	ln.Close()

	return l
}

func TestCheckRecognisesEachSituation(t *testing.T) {
	l := buildFullLab(t)

	tests := []struct {
		host        string
		status      Level
		codes       []string
		trusted     bool
		reasons     []string
		nameMatches bool
		tls10       Probe
		tls11       Probe
	}{
		{"valid.test", levelOK, nil, true, nil, true, probeRefused, probeRefused},
		{"expired.test", levelFail, []string{codeExpired}, false, []string{reasonExpired}, true, probeRefused, probeRefused},
		{"soon.test", levelWarn, []string{codeExpiringSoon}, true, nil, true, probeRefused, probeRefused},
		{"wrongname.test", levelFail, []string{codeNameMismatch}, true, nil, false, probeRefused, probeRefused},
		{"selfsigned.test", levelFail, []string{codeSelfSigned}, false, []string{reasonSelfSigned}, true, probeRefused, probeRefused},
		{"notyet.test", levelFail, []string{codeNotYetValid}, false, []string{reasonNotYetValid}, true, probeRefused, probeRefused},
		{"oldtls.test", levelWarn, []string{codeTLS10On, codeTLS11On}, true, nil, true, probeAccepted, probeAccepted},
		{"legacy.test", levelFail, []string{codeOldTLSOnly, codeTLS10On, codeTLS11On}, true, nil, true, probeAccepted, probeAccepted},
		{"weakcipher.test", levelWarn, []string{codeWeakCipher}, true, nil, true, probeRefused, probeRefused},
		{"missingint.test", levelFail, []string{codeMissingIntermediate}, false, []string{reasonMissingIntermediate}, true, probeRefused, probeRefused},
		{"unknownca.test", levelFail, []string{codeUnknownAuthority}, false, []string{reasonUnknownAuthority}, true, probeRefused, probeRefused},
		{"expiredself.test", levelFail, []string{codeExpired, codeSelfSigned}, false, []string{reasonExpired, reasonSelfSigned}, true, probeRefused, probeRefused},
	}

	var targets []Target
	for _, tc := range tests {
		targets = append(targets, mustTarget(t, tc.host))
	}
	targets = append(targets, mustTarget(t, "down.test"))

	// All sites at once, in parallel, so the race detector sees the real thing.
	results := l.checker(30, 5*time.Second).CheckAll(context.Background(), targets, 4)
	byHost := map[string]Result{}
	for _, r := range results {
		byHost[r.Host] = r
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			r := byHost[tc.host]
			if r.Status != tc.status {
				t.Errorf("status = %s, want %s; findings: %+v", r.Status, tc.status, r.Findings)
			}
			if got := codesOf(r); !slices.Equal(got, tc.codes) {
				t.Errorf("finding codes = %v, want %v", got, tc.codes)
			}
			if r.Certificate == nil {
				t.Fatalf("no certificate details; error: %s", r.Error)
			}
			c := r.Certificate
			if c.Trusted != tc.trusted {
				t.Errorf("trusted = %v, want %v", c.Trusted, tc.trusted)
			}
			if !slices.Equal(c.UntrustedReasons, tc.reasons) {
				t.Errorf("untrusted reasons = %q, want %q", c.UntrustedReasons, tc.reasons)
			}
			if c.NameMatches != tc.nameMatches {
				t.Errorf("name matches = %v, want %v", c.NameMatches, tc.nameMatches)
			}
			if r.TLS10 != tc.tls10 || r.TLS11 != tc.tls11 {
				t.Errorf("TLS 1.0 = %s, TLS 1.1 = %s, want %s and %s", r.TLS10, r.TLS11, tc.tls10, tc.tls11)
			}
			for _, f := range r.Findings {
				if strings.TrimSpace(f.Message) == "" {
					t.Errorf("finding %s has no message", f.Code)
				}
			}
		})
	}

	t.Run("down.test", func(t *testing.T) {
		r := byHost["down.test"]
		if r.Status != levelFail || !slices.Equal(codesOf(r), []string{codeCannotConnect}) {
			t.Fatalf("got %s %v, want FAIL cannot_connect", r.Status, codesOf(r))
		}
		if r.Certificate != nil {
			t.Error("a site we could not reach should have no certificate details")
		}
		if !strings.Contains(r.Error, "port 443") {
			t.Errorf("error %q should mention the port", r.Error)
		}
	})

	t.Run("details of a good site", func(t *testing.T) {
		r := byHost["valid.test"]
		c := r.Certificate
		if c.SubjectCN != "valid.test" {
			t.Errorf("subject CN = %q", c.SubjectCN)
		}
		if c.Issuer != "Test Intermediate, Test Org" {
			t.Errorf("issuer = %q", c.Issuer)
		}
		if !slices.Equal(c.DNSNames, []string{"valid.test", "www.valid.test"}) {
			t.Errorf("DNS names = %v", c.DNSNames)
		}
		if c.DaysLeft != 200 {
			t.Errorf("days left = %d, want 200", c.DaysLeft)
		}
		if c.KeyType != "ECDSA" || c.KeyBits != 256 {
			t.Errorf("key = %s %d, want ECDSA 256", c.KeyType, c.KeyBits)
		}
		if c.SignatureAlgorithm != "ECDSA-SHA256" {
			t.Errorf("signature algorithm = %q", c.SignatureAlgorithm)
		}
		if c.ChainSent != 2 {
			t.Errorf("certificates sent = %d, want 2", c.ChainSent)
		}
		if r.TLSVersion != "TLS 1.3" {
			t.Errorf("TLS version = %q, want TLS 1.3", r.TLSVersion)
		}
		if r.CipherSuite == "" {
			t.Error("cipher suite is empty")
		}
	})

	t.Run("expiring soon counts whole days", func(t *testing.T) {
		if got := byHost["soon.test"].Certificate.DaysLeft; got != 10 {
			t.Errorf("days left = %d, want 10", got)
		}
		if got := byHost["expired.test"].Certificate.DaysLeft; got != -3 {
			t.Errorf("days left = %d, want -3", got)
		}
	})

	t.Run("legacy site negotiates an old version", func(t *testing.T) {
		if got := byHost["legacy.test"].TLSVersion; got != "TLS 1.1" {
			t.Errorf("TLS version = %q, want TLS 1.1", got)
		}
	})

	t.Run("intermediate download sends the RavGB user agent", func(t *testing.T) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if len(l.aiaAgents) == 0 {
			t.Fatal("the missing intermediate was never downloaded")
		}
		for _, ua := range l.aiaAgents {
			if ua != userAgent {
				t.Errorf("User-Agent = %q, want %q", ua, userAgent)
			}
		}
	})
}

func TestWarnWindow(t *testing.T) {
	l := newLab(t)
	now := time.Now()
	leaf, key := newLeaf(t, l.inter, leafSpec{names: []string{"soon.test"}, notBefore: now.Add(-days(80)), notAfter: now.Add(days(10.2))})
	l.site(t, "soon.test", chainFor(leaf, key, l.inter.cert), nil)
	target := mustTarget(t, "soon.test")

	for _, tc := range []struct {
		warnDays int
		want     Level
	}{
		{30, levelWarn},
		{11, levelWarn},
		{10, levelOK}, // 10 days and some hours left is not "within 10 days"
		{5, levelOK},
		{0, levelOK},
	} {
		r := l.checker(tc.warnDays, 5*time.Second).Check(context.Background(), target)
		if r.Status != tc.want {
			t.Errorf("-warn %d: status = %s, want %s (%v)", tc.warnDays, r.Status, tc.want, codesOf(r))
		}
	}
}

func TestSilentServerTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c) // accept, then never answer
			mu.Unlock()
		}
	})
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	})

	fn := fakeNet{"silent.test:443": ln.Addr().String()}
	c := newChecker(30, 300*time.Millisecond, withDialer(fn.dial))
	start := time.Now()
	r := c.Check(context.Background(), mustTarget(t, "silent.test"))
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("check took %s, the timeout was not applied", took)
	}
	if r.Status != levelFail || !slices.Equal(codesOf(r), []string{codeCannotConnect}) {
		t.Fatalf("got %s %v, want FAIL cannot_connect", r.Status, codesOf(r))
	}
	if !strings.Contains(r.Error, "within 300ms") {
		t.Errorf("error %q should say how long we waited", r.Error)
	}
}

func TestCheckAllStopsWhenCancelled(t *testing.T) {
	l := buildFullLab(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	targets := []Target{mustTarget(t, "valid.test"), mustTarget(t, "soon.test")}
	results := l.checker(30, 5*time.Second).CheckAll(ctx, targets, 1)
	for _, r := range results {
		if r.Status != levelFail || !slices.Equal(codesOf(r), []string{codeNotChecked}) {
			t.Errorf("%s: got %s %v, want FAIL not_checked", r.Site, r.Status, codesOf(r))
		}
	}
	if fixes := topFixes(results); len(fixes) != 0 {
		t.Errorf("sites that were never checked should not produce fixes: %q", fixes)
	}
}

func TestSortResults(t *testing.T) {
	l := buildFullLab(t)
	var targets []Target
	for _, h := range []string{"valid.test", "soon.test", "down.test", "expired.test", "expiredself.test"} {
		targets = append(targets, mustTarget(t, h))
	}
	results := l.checker(30, 5*time.Second).CheckAll(context.Background(), targets, 5)
	sortResults(results)
	var got []string
	for _, r := range results {
		got = append(got, r.Host)
	}
	want := []string{"down.test", "expiredself.test", "expired.test", "soon.test", "valid.test"}
	if !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// Two sites that share one certificate are checked a moment apart, so their
// time left differs by a little. They must still keep the order given.
func TestSortResultsKeepsOrderForSameExpiry(t *testing.T) {
	end := time.Now().Add(days(45))
	mk := func(site string, remaining time.Duration) Result {
		return Result{Site: site, Certificate: &CertInfo{NotAfter: end}, remaining: remaining}
	}
	rs := []Result{mk("first.test", days(45)+time.Millisecond), mk("second.test", days(45))}
	sortResults(rs)
	if rs[0].Site != "first.test" {
		t.Errorf("order = %s, %s; sites with the same expiry should keep the order given", rs[0].Site, rs[1].Site)
	}
}

func mustTarget(t *testing.T, s string) Target {
	t.Helper()
	tg, err := parseTarget(s)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func codesOf(r Result) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}
