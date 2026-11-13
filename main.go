// Command ssl-check checks the HTTPS certificates of a list of sites in
// parallel and warns before one expires.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"
)

// Exit codes.
const (
	exitOK       = 0 // the run completed and every site is OK
	exitProblems = 1 // at least one site is WARN or FAIL
	exitError    = 2 // usage error, or the run could not complete
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usageText = `ssl-check checks the HTTPS certificates of one or more sites and warns
before one expires. Sites are checked in parallel.

Usage:
  ssl-check [flags] site [site ...]
  ssl-check [flags] -f sites.txt

A site can be a name (example.com), a name and a port (example.com:8443)
or a web address (https://example.com/shop). The default port is 443.
In a file, put one site per line. Lines starting with # are ignored.

Flags:
`

const usageFooter = `
Status for each site:
  OK    certificate valid, trusted and not close to expiry
  WARN  expires within -warn days, or TLS 1.0 / TLS 1.1 still accepted
  FAIL  expired, not yet valid, wrong name, not trusted, or cannot connect

Exit codes:
  0  the run completed and every site is OK
  1  at least one site is WARN or FAIL (handy for cron)
  2  usage error, or the run could not complete

Examples:
  ssl-check example.com www.example.com
  ssl-check -warn 14 -f sites.txt
  ssl-check -json example.com > report.json

Made by RavGB, https://ravgb.com
`

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, opts ...Option) int {
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "", "read sites from `file`, one per line (use - for standard input)")
	warnDays := fs.Int("warn", 30, "warn when a certificate expires within this many `days`")
	concurrency := fs.Int("concurrency", 10, "how many sites to check at the same time")
	timeout := fs.Duration("timeout", 10*time.Second, "time limit for each connection attempt")
	asJSON := fs.Bool("json", false, "print machine-readable JSON instead of the text report")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprint(out, usageText)
		fs.PrintDefaults()
		fmt.Fprint(out, usageFooter)
	}

	sites, err := parseArgs(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		return exitError // the flag package already printed the problem and the usage
	}

	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "ssl-check: "+format+"\n", a...)
		return exitError
	}
	switch {
	case *warnDays < 0 || *warnDays > 3650:
		return fail("-warn must be a number of days from 0 to 3650")
	case *concurrency < 1:
		return fail("-concurrency must be 1 or more")
	case *timeout <= 0:
		return fail("-timeout must be more than 0, for example 10s")
	}

	if *file != "" {
		fromFile, err := readSiteFile(*file, stdin)
		if err != nil {
			return fail("could not read the site list: %v", err)
		}
		sites = append(sites, fromFile...)
	}
	if len(sites) == 0 {
		fmt.Fprintln(stderr, "ssl-check: no sites given. Name at least one site, or use -f file.")
		fmt.Fprintln(stderr, "Run ssl-check -h for help.")
		return exitError
	}
	targets, err := buildTargets(sites)
	if err != nil {
		return fail("some sites are not valid:\n%v", err)
	}

	checker := newChecker(*warnDays, *timeout, opts...)
	start := time.Now()
	results := checker.CheckAll(ctx, targets, *concurrency)
	sortResults(results)
	rep := buildReport(results, *warnDays, start)

	if *asJSON {
		err = writeJSON(stdout, rep)
	} else {
		err = writeText(stdout, rep)
	}
	if err != nil {
		return fail("could not write the report: %v", err)
	}
	if ctx.Err() != nil {
		return fail("stopped before every site was checked")
	}
	if rep.hasProblems() {
		return exitProblems
	}
	return exitOK
}

// parseArgs lets flags and sites be mixed, so "ssl-check example.com -json"
// works as well as "ssl-check -json example.com". Everything after "--" is
// a site.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var sites []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		consumed := args[:len(args)-len(rest)]
		if len(consumed) > 0 && consumed[len(consumed)-1] == "--" {
			return append(sites, rest...), nil
		}
		if len(rest) == 0 {
			return sites, nil
		}
		sites = append(sites, rest[0])
		args = rest[1:]
	}
}

func readSiteFile(path string, stdin io.Reader) ([]string, error) {
	if path == "-" {
		return readSiteList(stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readSiteList(f)
}
