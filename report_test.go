package main

import (
	"bytes"
	"crypto/tls"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDescribeDays(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{days(63.5), "in 63 days"},
		{days(1.2), "in 1 day"},
		{days(0.4), "in less than a day"},
		{-days(0.4), "less than a day ago"},
		{-days(1.5), "1 day ago"},
		{-days(3.2), "3 days ago"},
	} {
		if got := describeDays(tc.d); got != tc.want {
			t.Errorf("describeDays(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestJoinSites(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a and b"},
		{[]string{"a", "b", "c"}, "a, b and c"},
		{[]string{"a", "b", "c", "d", "e"}, "a, b, c and 2 more sites"},
	} {
		if got := joinSites(tc.in); got != tc.want {
			t.Errorf("joinSites(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWrap(t *testing.T) {
	text := strings.Repeat("word ", 40)
	out := wrap(text, "  1. ", "     ")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected several lines, got %q", out)
	}
	for i, l := range lines {
		if len(l) > wrapWidth {
			t.Errorf("line %d is %d characters: %q", i, len(l), l)
		}
		prefix := "     word"
		if i == 0 {
			prefix = "  1. word"
		}
		if !strings.HasPrefix(l, prefix) {
			t.Errorf("line %d = %q, want prefix %q", i, l, prefix)
		}
	}
}

// goodInfo is a healthy certificate expiring in 100 days.
func goodInfo(now time.Time) *CertInfo {
	return &CertInfo{
		SubjectCN: "a.test", Issuer: "Test CA", DNSNames: []string{"a.test"},
		NotBefore: now.Add(-days(10)), NotAfter: now.Add(days(100)),
		NameMatches: true, Trusted: true, KeyType: "ECDSA", KeyBits: 256,
		SignatureAlgorithm: "ECDSA-SHA256",
	}
}

func TestAssessKeyAndCipherFindings(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name    string
		tweak   func(*CertInfo)
		version uint16
		cipher  uint16
		want    []string
	}{
		{"healthy", func(*CertInfo) {}, tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, nil},
		{"small RSA key", func(c *CertInfo) { c.KeyType, c.KeyBits = "RSA", 1024 }, tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, []string{codeSmallKey}},
		{"RSA 2048 is fine", func(c *CertInfo) { c.KeyType, c.KeyBits = "RSA", 2048 }, tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, nil},
		{"RSA key exchange", func(*CertInfo) {}, tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, []string{codeWeakCipher}},
		{"chain problem", func(c *CertInfo) { c.Trusted, c.UntrustedReasons = false, []string{reasonOtherPrefix + "x509: odd"} }, tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, []string{codeChainNotTrusted}},
		{"expired intermediate", func(c *CertInfo) { c.Trusted, c.UntrustedReasons = false, []string{reasonChainExpired} }, tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, []string{codeExpiredIntermediate}},
		{"weak signature", func(c *CertInfo) { c.Trusted, c.UntrustedReasons = false, []string{reasonWeakSignature} }, tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, []string{codeWeakSignature}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := goodInfo(now)
			tc.tweak(c)
			r := Result{Site: "a.test", Host: "a.test", Port: "443", Certificate: c, TLS10: probeRefused, TLS11: probeRefused}
			assess(&r, tc.version, tc.cipher, days(30), now)
			if got := codesOf(r); !slices.Equal(got, tc.want) {
				t.Errorf("codes = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTopFixesGroupsSitesAndKeepsPriority(t *testing.T) {
	mk := func(site string, codes ...string) Result {
		r := Result{Site: site}
		for _, c := range codes {
			r.add(levelWarn, c, "x")
		}
		return r
	}
	got := topFixes([]Result{
		mk("a.test", codeTLS10On, codeTLS11On),
		mk("b.test", codeTLS11On),
		mk("c.test", codeExpired),
		mk("d.test"),
	})
	if len(got) != 2 {
		t.Fatalf("got %d fixes, want 2: %q", len(got), got)
	}
	if !strings.HasPrefix(got[0], "Renew the certificate on c.test now") {
		t.Errorf("first fix = %q", got[0])
	}
	if !strings.Contains(got[1], "on a.test and b.test.") {
		t.Errorf("TLS fix should list both sites once: %q", got[1])
	}
}

func TestTextReportCapsTopFixes(t *testing.T) {
	now := time.Now()
	r := Result{Site: "a.test", Host: "a.test", Status: levelFail}
	for _, code := range []string{codeCannotConnect, codeExpired, codeNotYetValid, codeNameMismatch, codeSelfSigned, codeMissingIntermediate, codeExpiringSoon} {
		r.add(levelFail, code, "Problem "+code+".")
	}
	rep := buildReport([]Result{r}, 30, now)
	var buf bytes.Buffer
	if err := writeText(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "  5. ") || strings.Contains(out, "  6. ") {
		t.Errorf("text report should show 5 fixes:\n%s", out)
	}
	if !strings.Contains(out, "Plus 2 more. See the problems listed under each site above.") {
		t.Errorf("text report should say how many fixes were left out:\n%s", out)
	}
	if len(rep.TopFixes) != 7 {
		t.Errorf("JSON should keep all %d fixes, has %d", 7, len(rep.TopFixes))
	}
}

func TestTextReportForStoppedRun(t *testing.T) {
	rep := buildReport([]Result{stoppedResult(mustTarget(t, "a.test"))}, 30, time.Now())
	var buf bytes.Buffer
	if err := writeText(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "The run was stopped before every site was checked.") || strings.Contains(out, "Nothing to fix") {
		t.Errorf("a stopped run should not say there is nothing to fix:\n%s", out)
	}
	if rep.Summary.Fail != 1 || !rep.hasProblems() {
		t.Errorf("a site that was not checked should count as FAIL: %+v", rep.Summary)
	}
}
