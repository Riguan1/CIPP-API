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
$ wp-audit scan -f customers.txt --only-changes    # only what changed since last time
$ wp-audit update --alert-known                    # "does today's feed affect my customers?"
$ wp-audit history klant.nl                        # how that site has trended
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
vulnerability database — and indexes it into a local SQLite file. Scans then match against that
copy, so:

* one download covers any number of sites and any number of plugins;
* scans keep working with no internet access to the feed at all;
* there is no per-scan rate limit to work around.

### Getting a token

The feed is free, but **v3 requires an API token**. Register a free account at
[wordfence.com](https://www.wordfence.com/), then generate a token under **Integrations** in the
account dashboard. v2 was open to anyone and is being retired, so v3 is the default here.

```bash
export WORDFENCE_API_TOKEN='your-token'      # preferred: a token on the command line
wp-audit update                              # shows up in `ps` and shell history

wp-audit update --wordfence-token 'your-token'   # if you must
wp-audit update --feed-version v2                # no token, only while v2 still answers
```

A missing or rejected token is reported as exactly that, with the link to fix it — not as a network
error, which is what it otherwise looks like from the outside.

```bash
wp-audit update                          # ~/.cache/wp-audit/vulndb.sqlite by default
wp-audit update --db /srv/wp-audit/vulndb.sqlite
wp-audit update --feed production        # fully analysed records; 'scanner' (default) also
                                         # carries vulnerabilities still being researched
wp-audit update --from-file feed.json    # air-gapped: download the feed elsewhere, no token needed
```

The database's age travels with every report, and a scan against data more than a week old says so
in its findings. A scan against a three-month-old database is not a clean bill of health.

Wordfence Intelligence data is CC BY-SA 4.0; the attribution it requires is printed by `update` and
carried in the report.

**WPScan** is supported as an optional second opinion for people who already pay for it
(`--wpscan-token`). It is per-component rather than bulk — one API request per plugin, and the free
tier allows 25 a day — so it is strictly opt-in and not a basis for sweeping a customer base.

## Staying current, and hearing about it

Two schedules, because they answer different questions.

### Nightly: has anything new been published?

```cron
WORDFENCE_API_TOKEN=your-token

15 3 * * *  /srv/wp-audit/.venv/bin/wp-audit update --alert-known \
              --db /srv/wp-audit/vulndb.sqlite --history /srv/wp-audit/history.sqlite -q
```

`--alert-known` is the part that matters. After indexing the new feed it checks it against the
component inventory from your past scans and reports only what is *newly* relevant:

```
3 new advisory match(es) against components already seen on 1 site(s):

  klant.nl
    - contact-form-7 5.7.0 | CVE-2023-6449 | CVSS 9.8 | fixed in 5.7.2
      Contact Form 7 <= 5.7.1 - Unauthenticated Arbitrary File Upload
```

No HTTP requests, no re-scanning, and it covers your customers *between* scans: a vulnerability
published this morning in a plugin you last scanned on Friday surfaces tonight. Run it again with
the same feed and it says nothing — only genuinely new matches are reported, so the alert does not
become the thing everybody filters.

### Daily or weekly: has anything changed on the sites?

```cron
30 3 * * *  /srv/wp-audit/.venv/bin/wp-audit scan -f /srv/wp-audit/customers.txt \
              --db /srv/wp-audit/vulndb.sqlite --history /srv/wp-audit/history.sqlite \
              --only-changes --fail-on-change
```

Every scan is recorded, and each one is compared with the previous scan of the same site.
`--only-changes` prints **only the difference, and nothing at all when there is none**:

```
klant.nl: B -> F (0/100, -38)
  ! new critical: A wp-config backup is downloadable
  ! new vulnerability on contact-form-7 5.7.0: CVE-2023-6449 (fixed in 5.7.2)

andere-klant.nl: C -> B (78/100, +8)
  + fixed: HSTS is not enabled
```

That silence is the whole notification system: cron mails you whatever a job prints, so a quiet
night sends no mail and a changed site does. No credentials, no integration, nothing to keep
working. Improvements are reported alongside regressions — they are what you show the customer at
the end of the month, and a batch of findings reappearing together is how you spot a site that was
restored from an old backup.

Things the diff deliberately does **not** call a change:

* A check that could not run this time (`Unknown`). "We could not see it" is not "they fixed it".
* A check group you switched off. Running with `--skip-exposure` does not report every exposure
  finding as resolved.
* A site that went unreachable. Its findings do not all vanish — it is reported as unreachable.

### Into Teams or Slack

```bash
wp-audit scan -f customers.txt --webhook "$TEAMS_URL" --webhook-format teams -q
wp-audit update --alert-known --webhook "$SLACK_URL" --webhook-format slack -q
```

Posted only when something changed. For Teams use a **Workflows** webhook ("When a Teams webhook
request is received") — the old Office 365 connectors that took MessageCards have been retired, and
this sends an Adaptive Card. A failed delivery is reported on stderr and never loses the findings:
they are still on stdout and in the history.

There is deliberately no SMTP client. It would mean this tool holding a mail password, and the
machine already has a way to send mail that is configured and monitored. Pipe the output, or use
the cron behaviour above.

### Looking back

```bash
wp-audit history                 # every site, with its last result
wp-audit history klant.nl        # that site's trend, most recent first
```

```
klant.nl - most recent first

  2026-09-17T03:30:11+00:00   82/100  B  WordPress 6.6.2
  2026-09-16T03:30:09+00:00   44/100  F  WordPress 6.6.2
```

History lives in `~/.cache/wp-audit/history.sqlite` (`--history` to move it, `--no-history` to
record nothing), keeps the last 50 scans per site (`--prune`), and stores each report whole, so an
old scan stays readable even after the checks change.

### Exit codes for the scheduler

| Code | Meaning |
| --- | --- |
| 0 | Nothing to report |
| 1 | Findings at or above `--fail-on`, something got worse under `--fail-on-change`, or `update --alert-known` found something |
| 2 | A site could not be scanned |
| 3 | The tool itself failed |

### Keeping the tool itself current

The checks and the feed parsers change as WordPress does. `git pull && pip install -e .` in the
checkout, and watch the repository's releases if you want to be told. The vulnerability *data* is
the part that has to be fresh daily; the code is not on that clock.

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

## Output

`--format text` (default), `json` or `html`.

The HTML report is a single self-contained file with no external stylesheet, font or script — it
survives being emailed, and it does not tell a CDN somewhere which sites you audited. The JSON
carries the findings and the change set from the same run, so whatever consumes it does not have to
store the previous scan and work the difference out again.

Exit codes are listed under [Staying current](#exit-codes-for-the-scheduler). A site that could not
be scanned never looks like a site that came back clean.

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
