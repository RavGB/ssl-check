package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runTool(t *testing.T, l *lab, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	var opts []Option
	if l != nil {
		opts = l.options()
	}
	code = run(context.Background(), args, strings.NewReader(stdin), &out, &errOut, opts...)
	return code, out.String(), errOut.String()
}

func TestRunJSONSortedWithExitCode1(t *testing.T) {
	l := buildFullLab(t)
	code, out, errOut := runTool(t, l, "", "-json", "valid.test", "expired.test", "soon.test")
	if code != exitProblems {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitProblems, errOut)
	}
	var rep Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	var order []string
	for _, r := range rep.Results {
		order = append(order, r.Site)
	}
	if strings.Join(order, " ") != "expired.test soon.test valid.test" {
		t.Errorf("order = %v, want soonest expiry first", order)
	}
	if rep.Summary != (Summary{Sites: 3, OK: 1, Warn: 1, Fail: 1}) {
		t.Errorf("summary = %+v", rep.Summary)
	}
	if len(rep.TopFixes) != 2 ||
		!strings.Contains(rep.TopFixes[0], "Renew the certificate on expired.test now") ||
		!strings.Contains(rep.TopFixes[1], "soon.test") {
		t.Errorf("top fixes = %q", rep.TopFixes)
	}
	if rep.Tool != "ssl-check" || rep.WarnDays != 30 {
		t.Errorf("tool = %q, warn days = %d", rep.Tool, rep.WarnDays)
	}
	if !strings.Contains(out, `"days_left": 10`) || !strings.Contains(out, `"tls1_0": "refused"`) {
		t.Errorf("JSON is missing expected fields:\n%s", out)
	}
}

func TestRunTextAllGoodExitsZero(t *testing.T) {
	l := buildFullLab(t)
	code, out, errOut := runTool(t, l, "", "valid.test")
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0; stderr: %s\n%s", code, errOut, out)
	}
	for _, want := range []string{
		"OK    valid.test",
		"No problems found.",
		"Name matches: yes",
		"TLS 1.0:      off (good)",
		"Summary: 1 site checked. 1 OK, 0 WARN, 0 FAIL.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\nTop fixes\n  Nothing to fix right now. Run this check regularly, for example once a day.\n") {
		t.Errorf("report should end with an empty Top fixes list:\n%s", out)
	}
}

func TestRunTextReportEndsWithTopFixesInPriorityOrder(t *testing.T) {
	l := buildFullLab(t)
	code, out, _ := runTool(t, l, "", "oldtls.test", "soon.test", "expired.test", "down.test", "wrongname.test", "valid.test")
	if code != exitProblems {
		t.Fatalf("exit code = %d, want 1", code)
	}
	i := strings.LastIndex(out, "\nTop fixes\n")
	if i < 0 {
		t.Fatalf("no Top fixes section:\n%s", out)
	}
	fixes := out[i:]
	order := []string{"1. Check that down.test", "2. Renew the certificate on expired.test", "3. Install a certificate on wrongname.test", "4. Renew the certificate on soon.test", "5. Turn off TLS 1.0 and TLS 1.1 on oldtls.test"}
	last := -1
	for _, want := range order {
		at := strings.Index(fixes, want)
		if at < 0 || at < last {
			t.Fatalf("fix %q missing or out of order:\n%s", want, fixes)
		}
		last = at
	}
	if strings.ContainsAny(out, "\u2013\u2014") {
		t.Error("report contains an en dash or em dash")
	}
	if strings.Index(out, "FAIL  down.test") > strings.Index(out, "OK    valid.test") {
		t.Error("sites should be listed most urgent first")
	}
}

func TestRunMixedFlagsAndSites(t *testing.T) {
	l := buildFullLab(t)
	code, out, errOut := runTool(t, l, "", "valid.test", "-json", "-warn", "5")
	if code != exitOK {
		t.Fatalf("exit code = %d; stderr: %s", code, errOut)
	}
	var rep Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("flags after the site were not applied: %v", err)
	}
	if rep.WarnDays != 5 {
		t.Errorf("warn days = %d, want 5", rep.WarnDays)
	}
}

func TestRunReadsSiteFileAndStdin(t *testing.T) {
	l := buildFullLab(t)
	path := filepath.Join(t.TempDir(), "sites.txt")
	list := "# my sites\nvalid.test\n\nhttps://valid.test/shop  # same site again\nsoon.test, oldtls.test\n"
	if err := os.WriteFile(path, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
	}{
		{"file", "", []string{"-json", "-f", path}},
		{"stdin", list, []string{"-json", "-f", "-"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runTool(t, l, tc.stdin, tc.args...)
			if code != exitProblems {
				t.Fatalf("exit code = %d; stderr: %s", code, errOut)
			}
			var rep Report
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Summary.Sites != 3 {
				t.Errorf("checked %d sites, want 3 (duplicates removed)", rep.Summary.Sites)
			}
		})
	}
}

func TestRunUsageErrorsExit2(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no sites", nil, "no sites given"},
		{"unknown flag", []string{"-nope", "a.test"}, "flag provided but not defined"},
		{"negative warn", []string{"-warn", "-1", "a.test"}, "-warn"},
		{"huge warn", []string{"-warn", "99999999999", "a.test"}, "-warn"},
		{"zero concurrency", []string{"-concurrency", "0", "a.test"}, "-concurrency"},
		{"zero timeout", []string{"-timeout", "0s", "a.test"}, "-timeout"},
		{"bad site", []string{"bad site!"}, "not valid"},
		{"bad port", []string{"a.test:99999"}, "port"},
		{"missing file", []string{"-f", filepath.Join(t.TempDir(), "nope.txt")}, "could not read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runTool(t, nil, "", tc.args...)
			if code != exitError {
				t.Errorf("exit code = %d, want 2", code)
			}
			if out != "" {
				t.Errorf("nothing should go to stdout on a usage error, got %q", out)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Errorf("stderr %q should mention %q", errOut, tc.want)
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	code, _, errOut := runTool(t, nil, "", "-h")
	if code != exitOK {
		t.Errorf("exit code = %d, want 0", code)
	}
	for _, want := range []string{"Usage:", "-warn", "-concurrency", "-timeout", "-json", "-f file", "Exit codes:", "https://ravgb.com"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("help is missing %q", want)
		}
	}
}

// The writing rules for this project forbid en and em dashes anywhere.
func TestNoLongDashesInSourceOrDocs(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "README.md")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.ContainsAny(b, "\u2013\u2014") {
			t.Errorf("%s contains an en dash or em dash", f)
		}
	}
}
