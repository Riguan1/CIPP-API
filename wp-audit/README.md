# wp-audit

A passive, read-only security scanner for WordPress websites, with a local vulnerability database
that keeps itself current.

Built for the case where you look after other people's WordPress sites and need to know, per site
and on a schedule: is anything on it publicly known to be vulnerable, is it configured badly, and
what do I tell the customer.

```
$ wp-audit update                              # refresh the vulnerability database (nightly cron)
$ wp-audit scan example.com                    # scan one site
$ wp-audit scan -f customers.txt --format html -o report.html
```

## Before you scan

**Scan only sites you own or are engaged to assess.** Every request this makes is one an ordinary
visitor could make, and nothing here can damage a site — but pointing a scanner at a third party's
website without permission is still unauthorised scanning under the Dutch Wet computercriminaliteit,
the UK Computer Misuse Act and equivalents elsewhere. Get it in the engagement letter.

## Install

Python 3.10 or newer.

```bash
git clone <your-repo> wp-audit && cd wp-audit
python3 -m venv .venv && .venv/bin/pip install -e ".[tls]"
.venv/bin/wp-audit --help
```

`requests` is the only hard dependency. `cryptography` (the `tls` extra) is optional and only
affects how much detail you get about a certificate that fails validation.

## The vulnerability database

This is what makes the scanner stay useful over time rather than going stale the day it is written.

`wp-audit update` downloads the **Wordfence Intelligence** vulnerability feed — the full WordPress
vulnerability database, free, no API key — and indexes it into a local SQLite file. Scans then match
against that copy, so:

* one download covers any number of sites and any number of plugins;
* scans keep working with no internet access to the feed at all;
* there is no per-scan rate limit to work around.

```bash
wp-audit update                      # ~/.cache/wp-audit/vulndb.sqlite by default
wp-audit update --db /srv/wp-audit/vulndb.sqlite
wp-audit update --from-file feed.json   # air-gapped: download the feed elsewhere
```

Put it in cron and the scanner is as current as the feed:

```cron
15 3 * * *  /srv/wp-audit/.venv/bin/wp-audit update -q --db /srv/wp-audit/vulndb.sqlite
30 3 * * *  /srv/wp-audit/.venv/bin/wp-audit scan -f /srv/wp-audit/customers.txt \
              --db /srv/wp-audit/vulndb.sqlite --format html -o /srv/reports/$(date +\%F).html -q
```

The database's age travels with every report, and a scan against data more than a week old says so
in its findings. A scan against a three-month-old database is not a clean bill of health.

Wordfence Intelligence data is CC BY-SA 4.0; the attribution it requires is printed by `update` and
carried in the report.

**WPScan** is supported as an optional second opinion for people who already pay for it
(`--wpscan-token`). It is per-component rather than bulk — one API request per plugin, and the free
tier allows 25 a day — so it is strictly opt-in and not a basis for sweeping a customer base.

## What a scan checks

| Area | Checks |
| --- | --- |
| **Vulnerabilities** | Core, plugin and theme versions matched against every advisory in the local database, with CVE, CVSS and the version that fixes it |
| Transport | HTTPS in use, HTTP→HTTPS redirect, certificate validity, expiry, hostname match, key size, negotiated TLS version, mixed content |
| Headers | HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, cookie `Secure`/`HttpOnly`, version banners, PHP branch against the support calendar |
| WordPress | Core version detection and currency, version disclosure, PHP errors shown to visitors |
| Components | Plugin and theme inventory, each compared against its WordPress.org release |
| Exposure | `wp-config` backups, `.env`, `.git`, debug logs, `readme.html`, the installer, directory listings, XML-RPC, `wp-cron.php` |
| Enumeration | Account names via the REST API and via author archives |

Each finding carries a severity, the evidence it came from and a recommendation. The scan is scored
out of 100 and graded A–F, weighted so that one critical finding outranks any number of small ones.

## What it deliberately does not do

**It does not exploit anything.** Every request is a plain GET for a path an anonymous visitor could
already request. Nothing is submitted, no password is tried, nothing is uploaded, and no input is
crafted to provoke an error. That is what makes it safe to run against a live customer site during
business hours, and it is also the limit: this finds misconfiguration, missing updates and published
vulnerabilities — not logic flaws, not anything behind a login.

**Vulnerability matches are version matches.** A match means the version the site reports falls
inside a published advisory's affected range. That is exactly what an attacker checks, from the same
public data, which is why it is worth knowing. But:

* *False positives* — a host that backports security fixes without changing the version string, or a
  site whose version string is simply wrong, will match advisories it is not actually vulnerable to.
* *False negatives* — a component whose version cannot be read is not matched at all, and a
  vulnerability nobody has published yet cannot be matched by anyone.

So "no vulnerabilities match" means nothing is published for these versions today. The tool words it
that way on purpose, and you should too when you forward the report.

**Detection has blind spots.** Components are found from the assets the home page loads. An asset
optimiser that strips `?ver=` leaves a plugin with no version — invisible to matching. A site that
moves `wp-content` hides its plugins entirely. `--confirm-components` reads each component's
`readme.txt` to pin the version (one extra request each) and recovers most of the first case.

## Scanning safely

The scanner fetches URLs it is handed, so targets are resolved and pinned to the public internet
before any request is made, and again on every redirect hop: loopback, private, link-local
(including the `169.254.169.254` cloud metadata endpoint), carrier-grade NAT and reserved ranges are
refused, as are non-HTTP schemes, non-default ports and credentials in the URL. An open redirect on a
customer's site cannot be used to walk the scan into your own network.

Each site is capped at 30 requests by default (`--max-requests`). Checks that do not fit are reported
as `Unknown`, never as passes. No cookies are kept between requests, so every check sees the
anonymous view.

## Output and exit codes

`--format text` (default), `json` or `html`. The HTML report is a single self-contained file with no
external stylesheet, font or script — it survives being emailed, and it does not tell a CDN
somewhere which sites you audited.

For scheduled runs, `--fail-on <severity>` sets the exit code:

| Code | Meaning |
| --- | --- |
| 0 | Nothing at or above the threshold |
| 1 | Findings at or above `--fail-on` |
| 2 | A site could not be scanned (unreachable, or refused by the target guard) |
| 3 | The tool itself failed |

A site that could not be scanned never looks like a site that came back clean.

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

The end-to-end tests start a real HTTP server in-process and point the scanner at it, rather than
mocking the network. Most of this tool's failure modes live in the gap between what a server is
expected to send and what servers actually send — repeated `Set-Cookie` headers, soft 404s, redirect
chains — and a mock reproduces the expectation rather than the reality.

```
wpaudit/
  target.py         the guard: which URLs may be scanned at all
  probe.py          the single read-only request everything goes through
  fingerprint.py    WordPress detection, version, plugin and theme inventory
  versions.py       WordPress-style version comparison and range matching
  checks/           transport, headers, exposure, components, vulnerabilities
  vulndb/           the feeds and the local database
  scoring.py        findings to a score and a grade
  report.py         text, JSON and HTML rendering
  cli.py            the command line
```
