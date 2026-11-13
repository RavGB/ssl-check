# ssl-check

`ssl-check` looks at the HTTPS certificate of one site or a whole list of
sites, all at the same time, and tells you in plain words if anything is
wrong. Its main job is to warn you **before** a certificate runs out, so
your visitors never see a "Your connection is not private" page.

It is a single program with no setup. Run it by hand, or put it in cron and
let it tell you when something needs attention.

## What it checks, and why it matters

For every site it connects to the server much like a browser would, but it
also allows old TLS versions and cipher suites so it can report on them.
Then it reports:

- **When the certificate expires**, and how many days are left. An expired
  certificate puts a full-page security warning in front of every visitor.
  By default you get a warning 30 days ahead.
- **Whether it is valid yet.** A certificate with a start date in the future
  is rejected too.
- **Whether it covers the site name.** A certificate for `example.com` does
  not automatically cover `www.example.com`. The tool lists the names the
  certificate covers (the text report shows the first 8, `-json` lists all
  of them).
- **Whether browsers trust it**, and if not, why: expired, self-signed,
  issued by an unknown authority, or a missing intermediate certificate. A
  missing intermediate is easy to overlook because some desktop browsers
  work around it, while many phones, apps and tools refuse to connect.
- **Whether old TLS 1.0 and TLS 1.1 are still switched on.** These versions
  are outdated and have known weaknesses. They should be off. Current
  browsers no longer use them.
- **Technical details** for whoever looks after the server: who issued the
  certificate, the TLS version and cipher suite used, key type and size,
  and signature algorithm.

At the end you get a short **Top fixes** list, most urgent first.

## Install

You need Go 1.27 or newer.

```sh
go install github.com/RavGB/ssl-check@latest
```

The program lands in `$(go env GOPATH)/bin`, usually `~/go/bin/ssl-check`.

It only uses the Go standard library. No other modules are downloaded.

## Usage

```sh
# One site
ssl-check example.com

# Several sites, a custom port and a full web address all work
ssl-check example.com www.example.com shop.example.com:8443 https://example.com/blog

# A list of sites from a file (one per line, # starts a comment)
ssl-check -f sites.txt

# Warn 14 days ahead instead of 30
ssl-check -warn 14 -f sites.txt

# Machine-readable output
ssl-check -json -f sites.txt > report.json
```

A sites file can look like this:

```text
# Main sites
example.com
www.example.com

# Staging runs on another port
staging.example.com:8443
```

Flags (run `ssl-check -h` for the full help):

| Flag | Default | What it does |
| --- | --- | --- |
| `-f file` | | Read sites from a file. Use `-f -` to read from standard input. |
| `-warn days` | `30` | Warn when a certificate expires within this many days. |
| `-concurrency n` | `10` | How many sites to check at the same time. |
| `-timeout d` | `10s` | Time limit for each connection attempt. |
| `-json` | off | Print JSON instead of the text report. |

Flags can go before or after the site names.

## Sample output

This is a real run on 13 Nov 2026 against three public test sites from
badssl.com, which are set up on purpose with good and broken certificates:
one is fine, one has an expired certificate, and one does not send its
intermediate certificate.

```text
$ ssl-check tls-v1-2.badssl.com:1012 incomplete-chain.badssl.com expired.badssl.com
RavGB ssl-check
Checked 3 sites on 13 Nov 2026 at 19:25 UTC.
A certificate that expires within 30 days gets a warning.

FAIL  expired.badssl.com
      - The certificate expired on 12 Apr 2015 (4232 days ago). Visitors see a
        full-page security warning.
      - The server still accepts TLS 1.0. It is outdated, has known weaknesses
        and should be turned off.
      - The server still accepts TLS 1.1. It is outdated and should be turned
        off.
      Expires:      12 Apr 2015 (expired 4232 days ago)
      Valid from:   9 Apr 2015
      Issued to:    *.badssl.com
      Issued by:    COMODO RSA Domain Validation Secure Server CA, COMODO CA
                    Limited
      Covers:       *.badssl.com, badssl.com
      Name matches: yes
      Trusted:      no (expired)
      Connection:   TLS 1.2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      Key:          RSA 2048-bit, signed with SHA256-RSA
      TLS 1.0:      still on, should be turned off
      TLS 1.1:      still on, should be turned off

OK    tls-v1-2.badssl.com:1012
      No problems found.
      Expires:      28 Dec 2026 (in 45 days)
      Valid from:   29 Sep 2026
      Issued to:    *.badssl.com
      Issued by:    YR1, Let's Encrypt
      Covers:       *.badssl.com, badssl.com
      Name matches: yes
      Trusted:      yes
      Connection:   TLS 1.2, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      Key:          RSA 2048-bit, signed with SHA256-RSA
      TLS 1.0:      off (good)
      TLS 1.1:      off (good)

FAIL  incomplete-chain.badssl.com
      - The server does not send the intermediate certificate that links this
        certificate to a trusted authority. Some browsers fill the gap on
        their own, but many phones, apps and tools refuse to connect.
      - The server still accepts TLS 1.0. It is outdated, has known weaknesses
        and should be turned off.
      - The server still accepts TLS 1.1. It is outdated and should be turned
        off.
      Expires:      28 Dec 2026 (in 45 days)
      Valid from:   29 Sep 2026
      Issued to:    *.badssl.com
      Issued by:    YR1, Let's Encrypt
      Covers:       *.badssl.com, badssl.com
      Name matches: yes
      Trusted:      no (missing intermediate)
      Connection:   TLS 1.2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      Key:          RSA 2048-bit, signed with SHA256-RSA
      TLS 1.0:      still on, should be turned off
      TLS 1.1:      still on, should be turned off

Summary: 3 sites checked. 1 OK, 0 WARN, 2 FAIL.

Top fixes
  1. Renew the certificate on expired.badssl.com now. Visitors already see a
     security warning.
  2. Install the full certificate chain on incomplete-chain.badssl.com: the
     certificate plus its intermediate (often a file called fullchain).
  3. Turn off TLS 1.0 and TLS 1.1 on expired.badssl.com and
     incomplete-chain.badssl.com. Keep TLS 1.2 and TLS 1.3 on.
$ echo $?
1
```

The JSON output for one of these sites:

```json
{
  "tool": "ssl-check",
  "version": "0.1",
  "checked_at": "2026-11-13T19:25:52Z",
  "warn_days": 30,
  "summary": {
    "sites": 1,
    "ok": 0,
    "warn": 0,
    "fail": 1
  },
  "results": [
    {
      "site": "incomplete-chain.badssl.com",
      "input": "incomplete-chain.badssl.com",
      "host": "incomplete-chain.badssl.com",
      "port": "443",
      "status": "FAIL",
      "certificate": {
        "subject_cn": "*.badssl.com",
        "issuer": "YR1, Let's Encrypt",
        "valid_from": "2026-09-29T20:02:56Z",
        "valid_to": "2026-12-28T20:02:55Z",
        "days_left": 45,
        "dns_names": [
          "*.badssl.com",
          "badssl.com"
        ],
        "name_matches": true,
        "trusted": false,
        "untrusted_reasons": [
          "missing intermediate"
        ],
        "key_type": "RSA",
        "key_bits": 2048,
        "signature_algorithm": "SHA256-RSA",
        "certificates_sent": 1
      },
      "tls_version": "TLS 1.2",
      "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "tls1_0": "accepted",
      "tls1_1": "accepted",
      "findings": [
        {
          "level": "FAIL",
          "code": "missing_intermediate",
          "message": "The server does not send the intermediate certificate that links this certificate to a trusted authority. Some browsers fill the gap on their own, but many phones, apps and tools refuse to connect."
        },
        {
          "level": "WARN",
          "code": "tls1_0_on",
          "message": "The server still accepts TLS 1.0. It is outdated, has known weaknesses and should be turned off."
        },
        {
          "level": "WARN",
          "code": "tls1_1_on",
          "message": "The server still accepts TLS 1.1. It is outdated and should be turned off."
        }
      ]
    }
  ],
  "top_fixes": [
    "Install the full certificate chain on incomplete-chain.badssl.com: the certificate plus its intermediate (often a file called fullchain).",
    "Turn off TLS 1.0 and TLS 1.1 on incomplete-chain.badssl.com. Keep TLS 1.2 and TLS 1.3 on."
  ]
}
```

With `jq` you can pull out just what you need:

```sh
$ ssl-check -json tls-v1-2.badssl.com:1012 incomplete-chain.badssl.com expired.badssl.com | jq -r '.results[] | "\(.site) \(.status) \(.certificate.days_left)"'
expired.badssl.com FAIL -4232
tls-v1-2.badssl.com:1012 OK 45
incomplete-chain.badssl.com FAIL 45
```

## What the statuses mean

Sites are listed most urgent first: sites that could not be reached, then
the rest by days left, soonest first. Sites with the same expiry date keep
the order you gave them in.

| Status | Meaning |
| --- | --- |
| `OK` | Valid, trusted, covers the name, and not close to expiry. |
| `WARN` | Works today, but needs attention: expires within `-warn` days, TLS 1.0 or TLS 1.1 still accepted, an outdated cipher suite was used, or the key is too small (for example RSA under 2048 bits). |
| `FAIL` | Visitors are likely to see an error: expired, not yet valid, wrong name, not trusted, the server only offers TLS 1.1 or older, or the site could not be reached. |

In JSON, each problem has a stable `code`: `cannot_connect`, `not_checked`
(the run was stopped first), `expired`,
`not_yet_valid`, `name_mismatch`, `self_signed`, `unknown_authority`,
`missing_intermediate`, `expired_intermediate`, `weak_signature`,
`chain_not_trusted`, `old_tls_only`, `expiring_soon`, `tls1_0_on`,
`tls1_1_on`, `weak_cipher`, `small_key`. The `tls1_0` and `tls1_1` fields
are `accepted`, `refused` or `unknown` (no clear answer, for example a
timeout).

If the run is stopped with Ctrl+C, the sites that were not checked yet show
as `FAIL` with the code `not_checked`. The report then says how many sites
were checked before it stopped, and the JSON summary gets a `not_checked`
count.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The run completed and every site is OK. |
| `1` | The run completed and at least one site is WARN or FAIL. |
| `2` | Usage error (bad flag, bad site name, unreadable file), or the run was stopped before it finished. |

## Run it every day with cron

Because the exit code is 1 when something needs attention, cron can email
you only when there is a problem. This example runs every morning at 07:15
and uses the `mail` command, so the machine must be able to send email:

```cron
15 7 * * * $HOME/go/bin/ssl-check -f $HOME/sites.txt > $HOME/ssl-check.txt 2>&1 || mail -s "Certificate check needs attention" admin@example.com < $HOME/ssl-check.txt
```

## How it works

- Every site is checked in its own goroutine. A semaphore keeps at most
  `-concurrency` checks running at once, and every connection has its own
  `-timeout`. Pressing Ctrl+C cancels the checks still running, prints
  what was found so far (and how many sites were checked) and exits with
  code 2.
- The first connection accepts any certificate on purpose, so that broken
  certificates can still be inspected and explained. The tool then verifies
  the chain itself with Go's `crypto/x509` against the trust store of the
  computer it runs on (plus the intermediates the server sent), and checks
  the name separately. On macOS and Windows, Go asks the operating system to
  do this verification.
- The operating system can fill in a missing intermediate on its own, from
  its cache or by downloading it, and then call the chain trusted. So when
  the chain is trusted, the tool also compares it with the certificates the
  server actually sent. An intermediate the server did not send is reported
  as missing.
- When the chain is not trusted, the tool downloads the issuer certificate
  from the address written inside the certificate (the "Authority
  Information Access" field). If the chain becomes trusted with it, the
  problem is reported as a missing intermediate. This download is the only
  web request it makes, and it identifies itself with the User-Agent
  `RavGB-ssl-check/0.1 (+https://ravgb.com)`. Because the site being
  checked decides that address, the download only goes to public internet
  addresses. A link to a private, loopback or link-local address (such as
  the cloud metadata address 169.254.169.254) is skipped.
- TLS 1.0 and TLS 1.1 are tested with two extra connections, each one
  allowed to use only that version.
- Nothing is sent to the site beyond the TLS handshakes.

## What it does not check

- **Revocation.** It does not ask whether a certificate was revoked (OCSP or
  CRL).
- **Every server behind a name.** If a name points at several servers, it
  checks whichever one the connection reaches. Different servers could hold
  different certificates.
- **Every cipher suite.** It reports the one that was used, not the full list
  the server allows. A server that offers TLS 1.0 or 1.1 only with cipher
  suites Go does not implement (for example plain DHE suites) shows as
  `refused`.
- **The rest of the website.** It does not look at redirects from http to
  https, HSTS, mixed content, speed or anything else on the page.
- **Mail servers using STARTTLS.** Only services that start with TLS right
  away (like HTTPS) are supported.
- **International domain names** must be given in their ASCII form (the
  one that starts with `xn--`).
- **Intermediates kept on a private network.** The intermediate download
  skips private addresses, so for a certificate from a private authority a
  missing intermediate can be reported as an unknown authority instead.
- **Every browser's opinion.** Trust is judged by the computer running the
  tool. A particular browser or phone can occasionally disagree.

## Development

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

The tests need no internet. They create their own certificate authority and
certificates (valid, expired, expiring in 10 days, wrong name, self-signed,
not yet valid, missing intermediate, unknown authority, and more) and serve
them from local test servers, including servers that still accept TLS 1.0
and TLS 1.1. A stand-in for the macOS and Windows verifiers, which fills in
a missing intermediate on its own, checks that the tool still reports it.

## License

MIT. See [LICENSE](LICENSE).

---

Made by RavGB, https://ravgb.com

RavGB helps small teams with DevOps on AWS, websites and custom tools. A
free website check (speed, accessibility, search basics and how the site
works on a phone) and a free AWS audit are available at https://ravgb.com.
