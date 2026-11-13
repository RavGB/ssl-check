package main

import (
	"slices"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	for _, tc := range []struct {
		in, host, port, label string
	}{
		{"example.com", "example.com", "443", "example.com"},
		{"  Example.COM.  ", "example.com", "443", "example.com"},
		{"example.com:8443", "example.com", "8443", "example.com:8443"},
		{"example.com:", "example.com", "443", "example.com"},
		{"https://example.com/shop?x=1", "example.com", "443", "example.com"},
		{"https://user@example.com:9443/", "example.com", "9443", "example.com:9443"},
		{"http://example.com", "example.com", "443", "example.com"},
		{"example.com/path", "example.com", "443", "example.com"},
		{"192.0.2.10", "192.0.2.10", "443", "192.0.2.10"},
		{"192.0.2.10:8443", "192.0.2.10", "8443", "192.0.2.10:8443"},
		{"[2001:db8::1]:8443", "2001:db8::1", "8443", "[2001:db8::1]:8443"},
		{"[2001:db8::1]", "2001:db8::1", "443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1", "443", "2001:db8::1"},
		{"_dmarc-test.example.com", "_dmarc-test.example.com", "443", "_dmarc-test.example.com"},
	} {
		got, err := parseTarget(tc.in)
		if err != nil {
			t.Errorf("parseTarget(%q): %v", tc.in, err)
			continue
		}
		if got.Host != tc.host || got.Port != tc.port || got.Label() != tc.label {
			t.Errorf("parseTarget(%q) = %s / %s / %s, want %s / %s / %s",
				tc.in, got.Host, got.Port, got.Label(), tc.host, tc.port, tc.label)
		}
	}
}

func TestParseTargetRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		"https:///nohost",
		"exa mple.com",
		"*.example.com",
		"example..com",
		"example.com:0",
		"example.com:70000",
		"example.com:http",
		"bücher.example",
		strings.Repeat("a", 254),
	} {
		if got, err := parseTarget(in); err == nil {
			t.Errorf("parseTarget(%q) = %+v, want an error", in, got)
		}
	}
}

func TestReadSiteList(t *testing.T) {
	in := "# comment\n\na.test\nb.test, c.test   d.test # trailing\n  https://e.test/#frag\n"
	got, err := readSiteList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.test", "b.test", "c.test", "d.test", "https://e.test/"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildTargetsDedupesAndReportsEveryError(t *testing.T) {
	got, err := buildTargets([]string{"a.test", "A.TEST:443", "https://a.test/x", "a.test:8443", "bad site", "x.test:0"})
	if err == nil {
		t.Fatal("want an error for the invalid entries")
	}
	if !strings.Contains(err.Error(), "bad site") || !strings.Contains(err.Error(), "x.test:0") {
		t.Errorf("error should list every invalid entry, got: %v", err)
	}
	var addrs []string
	for _, tg := range got {
		addrs = append(addrs, tg.Addr())
	}
	if !slices.Equal(addrs, []string{"a.test:443", "a.test:8443"}) {
		t.Errorf("targets = %v", addrs)
	}
}
