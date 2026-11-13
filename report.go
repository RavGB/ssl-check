package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Summary counts sites by status. Sites that were not checked because the
// run was stopped count as FAIL, and are also counted in NotChecked.
type Summary struct {
	Sites      int `json:"sites"`
	OK         int `json:"ok"`
	Warn       int `json:"warn"`
	Fail       int `json:"fail"`
	NotChecked int `json:"not_checked,omitempty"`
}

// Report is the full output of one run.
type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	CheckedAt time.Time `json:"checked_at"`
	WarnDays  int       `json:"warn_days"`
	Summary   Summary   `json:"summary"`
	Results   []Result  `json:"results"`
	TopFixes  []string  `json:"top_fixes"`
}

func buildReport(results []Result, warnDays int, at time.Time) Report {
	rep := Report{
		Tool:      toolName,
		Version:   toolVersion,
		CheckedAt: at.UTC().Truncate(time.Second),
		WarnDays:  warnDays,
		Results:   results,
		TopFixes:  topFixes(results),
	}
	rep.Summary.Sites = len(results)
	for _, r := range results {
		switch r.Status {
		case levelOK:
			rep.Summary.OK++
		case levelWarn:
			rep.Summary.Warn++
		default:
			rep.Summary.Fail++
		}
		if hasAnyCode(r.Findings, []string{codeNotChecked}) {
			rep.Summary.NotChecked++
		}
	}
	return rep
}

// hasProblems reports whether any site is WARN or FAIL.
func (rep Report) hasProblems() bool { return rep.Summary.Warn+rep.Summary.Fail > 0 }

func writeJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

const (
	wrapWidth     = 78
	maxTopFixes   = 5
	maxNamesShown = 8
)

func writeText(w io.Writer, rep Report) error {
	var b strings.Builder
	sum := rep.Summary
	sites := "sites"
	if sum.Sites == 1 {
		sites = "site"
	}
	when := rep.CheckedAt.Format(dateLayout) + " at " + rep.CheckedAt.Format("15:04") + " UTC"
	checked := sum.Sites - sum.NotChecked
	fmt.Fprintf(&b, "RavGB ssl-check\n")
	if sum.NotChecked > 0 {
		b.WriteString(wrap(fmt.Sprintf("Checked %d of %d %s on %s. The run was stopped before the rest were checked.",
			checked, sum.Sites, sites, when), "", ""))
	} else {
		fmt.Fprintf(&b, "Checked %d %s on %s.\n", sum.Sites, sites, when)
	}
	if rep.WarnDays > 0 {
		fmt.Fprintf(&b, "A certificate that expires within %d days gets a warning.\n", rep.WarnDays)
	}

	for _, r := range rep.Results {
		b.WriteString("\n")
		writeSite(&b, r)
	}

	if sum.NotChecked > 0 {
		b.WriteString("\n" + wrap(fmt.Sprintf("Summary: %d %s, %d checked before the run was stopped. %d OK, %d WARN, %d FAIL (%d not checked).",
			sum.Sites, sites, checked, sum.OK, sum.Warn, sum.Fail, sum.NotChecked), "", ""))
	} else {
		fmt.Fprintf(&b, "\nSummary: %d %s checked. %d OK, %d WARN, %d FAIL.\n",
			sum.Sites, sites, sum.OK, sum.Warn, sum.Fail)
	}

	b.WriteString("\nTop fixes\n")
	switch {
	case len(rep.TopFixes) == 0 && sum.NotChecked > 0:
		b.WriteString(wrap("The run was stopped before every site was checked. Run it again to get a full answer.", "  ", "  "))
	case len(rep.TopFixes) == 0:
		b.WriteString(wrap("Nothing to fix right now. Run this check regularly, for example once a day.", "  ", "  "))
	}
	for i, fix := range rep.TopFixes {
		if i == maxTopFixes {
			fmt.Fprintf(&b, "  Plus %d more. See the problems listed under each site above.\n", len(rep.TopFixes)-maxTopFixes)
			break
		}
		num := fmt.Sprintf("  %d. ", i+1)
		b.WriteString(wrap(fix, num, strings.Repeat(" ", len(num))))
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeSite(b *strings.Builder, r Result) {
	fmt.Fprintf(b, "%-5s %s\n", r.Status, r.Site)
	if len(r.Findings) == 0 {
		b.WriteString("      No problems found.\n")
	} else {
		for _, f := range r.Findings {
			b.WriteString(wrap(f.Message, "      - ", "        "))
		}
	}
	c := r.Certificate
	if c == nil {
		return
	}
	expiry := describeDays(r.remaining)
	if r.remaining < 0 {
		expiry = "expired " + expiry
	}
	field(b, "Expires", fmt.Sprintf("%s (%s)", c.NotAfter.Format(dateLayout), expiry))
	field(b, "Valid from", c.NotBefore.Format(dateLayout))
	field(b, "Issued to", orDefault(c.SubjectCN, "(no name)"))
	field(b, "Issued by", c.Issuer)
	names := append(append([]string{}, c.DNSNames...), c.IPAddresses...)
	field(b, "Covers", orDefault(shortList(names, maxNamesShown), "(no names listed)"))
	field(b, "Name matches", yesNo(c.NameMatches))
	trusted := "yes"
	if !c.Trusted {
		trusted = "no (" + strings.Join(c.UntrustedReasons, ", ") + ")"
	}
	field(b, "Trusted", trusted)
	field(b, "Connection", r.TLSVersion+", "+r.CipherSuite)
	key := c.KeyType
	if c.KeyBits > 0 {
		key = fmt.Sprintf("%s %d-bit", c.KeyType, c.KeyBits)
	}
	field(b, "Key", key+", signed with "+c.SignatureAlgorithm)
	field(b, "TLS 1.0", probeText(r.TLS10))
	field(b, "TLS 1.1", probeText(r.TLS11))
}

func field(b *strings.Builder, label, value string) {
	b.WriteString(wrap(value, fmt.Sprintf("      %-14s", label+":"), strings.Repeat(" ", 20)))
}

func probeText(p Probe) string {
	switch p {
	case probeAccepted:
		return "still on, should be turned off"
	case probeRefused:
		return "off (good)"
	default:
		return "could not tell"
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// wrap breaks text into lines of at most wrapWidth characters. The first line
// starts with first, the others with rest.
func wrap(text, first, rest string) string {
	var b strings.Builder
	line := first
	empty := true
	for _, word := range strings.Fields(text) {
		if !empty && len(line)+1+len(word) > wrapWidth {
			b.WriteString(line + "\n")
			line, empty = rest, true
		}
		if !empty {
			line += " "
		}
		line += word
		empty = false
	}
	b.WriteString(line + "\n")
	return b.String()
}
