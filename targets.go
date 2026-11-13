package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

const defaultPort = "443"

// Target is one site to check.
type Target struct {
	Input string // what the user typed
	Host  string // name sent to the server (SNI) and checked against the certificate
	Port  string
}

// Addr is the host:port to connect to.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, t.Port) }

// Label is the short name used in reports. The port is left out when it is 443.
func (t Target) Label() string {
	if t.Port == defaultPort {
		return t.Host
	}
	return t.Addr()
}

// parseTarget accepts a host name, host:port, an IP address or a URL.
func parseTarget(s string) (Target, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return Target{}, errors.New("empty site name")
	}

	hostport := in
	if strings.Contains(in, "://") {
		u, err := url.Parse(in)
		if err != nil {
			return Target{}, fmt.Errorf("%q is not a valid address", in)
		}
		if u.Host == "" {
			return Target{}, fmt.Errorf("%q has no site name in it", in)
		}
		hostport = u.Host
	} else if i := strings.IndexAny(in, "/?#"); i >= 0 {
		// Allow "example.com/shop" without a scheme.
		hostport = in[:i]
	}

	host, port := hostport, defaultPort
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = hostport[1 : len(hostport)-1]
	}
	if port == "" {
		port = defaultPort
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if err := checkHostName(host); err != nil {
		return Target{}, fmt.Errorf("%q: %v", in, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Target{}, fmt.Errorf("%q: port %q is not a number from 1 to 65535", in, port)
	}
	return Target{Input: in, Host: host, Port: strconv.Itoa(n)}, nil
}

func checkHostName(host string) error {
	if host == "" {
		return errors.New("no site name")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 {
		return errors.New("site name is too long")
	}
	for _, r := range host {
		if r > unicode.MaxASCII {
			return errors.New("use the ASCII form of international names (it starts with xn--)")
		}
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return fmt.Errorf("site name contains %q, which is not allowed", r)
		}
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return errors.New("site name has an empty part (two dots in a row?)")
		}
	}
	return nil
}

// byteOrderMark is the invisible mark some Windows editors put at the start
// of a UTF-8 file (Windows PowerShell 5.1 and older Notepad, for example).
const byteOrderMark = '\uFEFF'

// readSiteList reads sites from a file: one or more per line, separated by
// spaces or commas. Blank lines and anything after # are ignored. Windows
// line endings and a byte order mark are fine.
func readSiteList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		out = append(out, strings.FieldsFunc(line, func(r rune) bool {
			return unicode.IsSpace(r) || r == ',' || r == byteOrderMark
		})...)
	}
	return out, sc.Err()
}

// buildTargets parses every site, drops duplicates (same host and port) and
// reports every invalid entry at once.
func buildTargets(sites []string) ([]Target, error) {
	var (
		out  []Target
		errs []error
		seen = make(map[string]bool)
	)
	for _, s := range sites {
		t, err := parseTarget(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[t.Addr()] {
			continue
		}
		seen[t.Addr()] = true
		out = append(out, t)
	}
	return out, errors.Join(errs...)
}
