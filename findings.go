package main

import (
	"crypto/tls"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Level is the status of one site, or the weight of one finding.
type Level string

const (
	levelOK   Level = "OK"
	levelWarn Level = "WARN"
	levelFail Level = "FAIL"
)

// Finding is one problem found on a site.
type Finding struct {
	Level   Level  `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is everything learned about one site.
type Result struct {
	Site        string    `json:"site"`
	Input       string    `json:"input"`
	Host        string    `json:"host"`
	Port        string    `json:"port"`
	Status      Level     `json:"status"`
	Error       string    `json:"error,omitempty"`
	Certificate *CertInfo `json:"certificate,omitempty"`
	TLSVersion  string    `json:"tls_version,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	TLS10       Probe     `json:"tls1_0,omitempty"`
	TLS11       Probe     `json:"tls1_1,omitempty"`
	Findings    []Finding `json:"findings"`

	remaining time.Duration // time until expiry when the site was checked
}

// Finding codes. They are stable and appear in the JSON output.
const (
	codeCannotConnect       = "cannot_connect"
	codeNotChecked          = "not_checked"
	codeExpired             = "expired"
	codeNotYetValid         = "not_yet_valid"
	codeNameMismatch        = "name_mismatch"
	codeSelfSigned          = "self_signed"
	codeUnknownAuthority    = "unknown_authority"
	codeMissingIntermediate = "missing_intermediate"
	codeExpiredIntermediate = "expired_intermediate"
	codeWeakSignature       = "weak_signature"
	codeChainNotTrusted     = "chain_not_trusted"
	codeOldTLSOnly          = "old_tls_only"
	codeExpiringSoon        = "expiring_soon"
	codeTLS10On             = "tls1_0_on"
	codeTLS11On             = "tls1_1_on"
	codeWeakCipher          = "weak_cipher"
	codeSmallKey            = "small_key"
)

func (r *Result) add(level Level, code, msg string) {
	r.Findings = append(r.Findings, Finding{Level: level, Code: code, Message: msg})
}

// finish sets the status from the worst finding.
func (r *Result) finish() {
	r.Status = levelOK
	for _, f := range r.Findings {
		if f.Level == levelFail {
			r.Status = levelFail
			return
		}
		if f.Level == levelWarn {
			r.Status = levelWarn
		}
	}
}

// failedResult is the result for a site we could not inspect at all.
func failedResult(t Target, why string) Result {
	r := Result{Site: t.Label(), Input: t.Input, Host: t.Host, Port: t.Port, Error: why}
	r.add(levelFail, codeCannotConnect, "Could not check this site: "+why+".")
	r.finish()
	return r
}

// stoppedResult is the result for a site whose check was cancelled, for
// example with Ctrl+C. It counts as FAIL but has no fix of its own.
func stoppedResult(t Target) Result {
	r := Result{Site: t.Label(), Input: t.Input, Host: t.Host, Port: t.Port, Error: "the run was stopped before this site was checked"}
	r.add(levelFail, codeNotChecked, "Not checked: the run was stopped before this site was finished.")
	r.finish()
	return r
}

const dateLayout = "2 Jan 2006"

// assess turns the facts in r into findings and a status.
func assess(r *Result, version, cipher uint16, warn time.Duration, now time.Time) {
	c := r.Certificate
	r.remaining = c.NotAfter.Sub(now)
	r.Findings = []Finding{}

	switch {
	case now.After(c.NotAfter):
		r.add(levelFail, codeExpired, fmt.Sprintf(
			"The certificate expired on %s (%s). Visitors see a full-page security warning.",
			c.NotAfter.Format(dateLayout), describeDays(r.remaining)))
	case now.Before(c.NotBefore):
		r.add(levelFail, codeNotYetValid, fmt.Sprintf(
			"The certificate does not become valid until %s, so visitors see a security warning. Check the certificate dates and that the clocks are right.",
			c.NotBefore.Format(dateLayout)))
	}

	if !c.NameMatches {
		r.add(levelFail, codeNameMismatch, fmt.Sprintf(
			"The certificate does not cover the name %s. %s Visitors see a security warning.",
			r.Host, coveredNames(c)))
	}

	for _, reason := range c.UntrustedReasons {
		switch reason {
		case reasonExpired, reasonNotYetValid:
			// Already reported above from the dates.
		case reasonSelfSigned:
			r.add(levelFail, codeSelfSigned,
				"The certificate is self-signed, so browsers and phones do not trust it and show a security warning.")
		case reasonUnknownAuthority:
			r.add(levelFail, codeUnknownAuthority,
				"The certificate comes from an authority that browsers and phones do not trust, so visitors see a security warning.")
		case reasonMissingIntermediate:
			r.add(levelFail, codeMissingIntermediate,
				"The server does not send the intermediate certificate that links this certificate to a trusted authority. Some browsers fill the gap on their own, but many phones, apps and tools refuse to connect.")
		case reasonChainExpired:
			r.add(levelFail, codeExpiredIntermediate,
				"A certificate further up the chain (an intermediate) has expired, so the chain is not trusted.")
		case reasonWeakSignature:
			r.add(levelFail, codeWeakSignature,
				"The certificate is signed with an outdated method (SHA-1 or older) that browsers no longer accept.")
		default:
			r.add(levelFail, codeChainNotTrusted,
				"The certificate chain could not be verified ("+strings.TrimPrefix(reason, reasonOtherPrefix)+").")
		}
	}

	if version != 0 && version < tls.VersionTLS12 {
		r.add(levelFail, codeOldTLSOnly, fmt.Sprintf(
			"The newest TLS version this server offers is %s. Current browsers refuse to connect to it.",
			tls.VersionName(version)))
	}

	if r.remaining >= 0 && r.remaining < warn {
		r.add(levelWarn, codeExpiringSoon, fmt.Sprintf(
			"The certificate expires on %s (%s). Renew it before then, or make sure automatic renewal is working.",
			c.NotAfter.Format(dateLayout), describeDays(r.remaining)))
	}

	if r.TLS10 == probeAccepted {
		r.add(levelWarn, codeTLS10On,
			"The server still accepts TLS 1.0. It is outdated, has known weaknesses and should be turned off.")
	}
	if r.TLS11 == probeAccepted {
		r.add(levelWarn, codeTLS11On,
			"The server still accepts TLS 1.1. It is outdated and should be turned off.")
	}

	if insecureCipher(cipher) {
		r.add(levelWarn, codeWeakCipher, fmt.Sprintf(
			"The connection used an outdated encryption method (%s). It should be turned off on the server.",
			tls.CipherSuiteName(cipher)))
	}

	if (c.KeyType == "RSA" && c.KeyBits < 2048) || (c.KeyType == "ECDSA" && c.KeyBits < 256) {
		r.add(levelWarn, codeSmallKey, fmt.Sprintf(
			"The %s key is only %d bits, which is too weak today. Use RSA with at least 2048 bits, or ECDSA.",
			c.KeyType, c.KeyBits))
	}

	r.finish()
}

func insecureCipher(id uint16) bool {
	for _, s := range tls.InsecureCipherSuites() {
		if s.ID == id {
			return true
		}
	}
	return false
}

// describeDays writes a duration until (or since) expiry in plain words.
func describeDays(d time.Duration) string {
	days := wholeDays(d)
	switch {
	case d < 0 && days == 0:
		return "less than a day ago"
	case d < 0 && days == -1:
		return "1 day ago"
	case d < 0:
		return fmt.Sprintf("%d days ago", -days)
	case days == 0:
		return "in less than a day"
	case days == 1:
		return "in 1 day"
	default:
		return fmt.Sprintf("in %d days", days)
	}
}

func coveredNames(c *CertInfo) string {
	names := append(append([]string{}, c.DNSNames...), c.IPAddresses...)
	if len(names) == 0 {
		return "It lists no site names at all."
	}
	return "It only covers: " + shortList(names, 5) + "."
}

// shortList joins up to max items and says how many were left out.
func shortList(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
}

// sortResults puts sites that could not be checked first, then the rest by
// expiry date, soonest (or most expired) first. Ties keep the order the
// sites were given in. The expiry date is compared rather than the time
// left, because each site is checked at a slightly different moment.
func sortResults(rs []Result) {
	slices.SortStableFunc(rs, func(a, b Result) int {
		aNone, bNone := a.Certificate == nil, b.Certificate == nil
		switch {
		case aNone && bNone:
			return 0
		case aNone:
			return -1
		case bNone:
			return 1
		}
		return a.Certificate.NotAfter.Compare(b.Certificate.NotAfter)
	})
}

// Top fixes, in priority order. Several finding codes can share one fix.
var fixRules = []struct {
	codes []string
	text  string // %s is the list of sites
	many  string // used instead of text for more than one site, if set
}{
	{[]string{codeCannotConnect}, "Check that %s is online and accepts secure connections. Nothing else could be checked there.",
		"Check that %s are online and accept secure connections. Nothing else could be checked there."},
	{[]string{codeExpired}, "Renew the certificate on %s now. Visitors already see a security warning.", ""},
	{[]string{codeNotYetValid}, "Check the certificate dates and the server clock on %s.", ""},
	{[]string{codeNameMismatch}, "Install a certificate on %s that covers the exact site name (add the www name too if you use it).", ""},
	{[]string{codeSelfSigned, codeUnknownAuthority}, "Replace the certificate on %s with one from a trusted authority, such as Let's Encrypt or AWS Certificate Manager.", ""},
	{[]string{codeMissingIntermediate}, "Install the full certificate chain on %s: the certificate plus its intermediate (often a file called fullchain).", ""},
	{[]string{codeExpiredIntermediate}, "Install the current intermediate certificate on %s. The certificate provider publishes it.", ""},
	{[]string{codeWeakSignature}, "Replace the certificate on %s with a new one signed with SHA-256 or better.", ""},
	{[]string{codeChainNotTrusted}, "Have someone look at the certificate chain on %s, which could not be verified.", ""},
	{[]string{codeOldTLSOnly}, "Upgrade the server software on %s so it supports TLS 1.2 and TLS 1.3.", ""},
	{[]string{codeExpiringSoon}, "Renew the certificate on %s soon, or confirm that automatic renewal is working.", ""},
	{[]string{codeTLS10On, codeTLS11On}, "Turn off TLS 1.0 and TLS 1.1 on %s. Keep TLS 1.2 and TLS 1.3 on.", ""},
	{[]string{codeWeakCipher}, "Turn off old encryption methods (cipher suites) on %s.", ""},
	{[]string{codeSmallKey}, "Replace the certificate on %s with one that uses a stronger key.", ""},
}

// topFixes groups findings from all sites into one list of fixes, most
// urgent first. Within a fix, sites keep the order of rs.
func topFixes(rs []Result) []string {
	sitesFor := make([][]string, len(fixRules))
	for _, r := range rs {
		for i, rule := range fixRules {
			if hasAnyCode(r.Findings, rule.codes) {
				sitesFor[i] = append(sitesFor[i], r.Site)
			}
		}
	}
	out := []string{}
	for i, rule := range fixRules {
		text := rule.text
		if len(sitesFor[i]) > 1 && rule.many != "" {
			text = rule.many
		}
		if len(sitesFor[i]) > 0 {
			out = append(out, fmt.Sprintf(text, joinSites(sitesFor[i])))
		}
	}
	return out
}

func hasAnyCode(fs []Finding, codes []string) bool {
	for _, f := range fs {
		if slices.Contains(codes, f.Code) {
			return true
		}
	}
	return false
}

// joinSites writes "a", "a and b", "a, b and c", "a, b, c and 1 more site"
// or "a, b, c and 4 more sites".
func joinSites(sites []string) string {
	const max = 3
	switch {
	case len(sites) == 1:
		return sites[0]
	case len(sites) <= max:
		return strings.Join(sites[:len(sites)-1], ", ") + " and " + sites[len(sites)-1]
	case len(sites) == max+1:
		return strings.Join(sites[:max], ", ") + " and 1 more site"
	default:
		return fmt.Sprintf("%s and %d more sites", strings.Join(sites[:max], ", "), len(sites)-max)
	}
}
