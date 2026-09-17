# WordPress security scanning

A passive, read-only assessment of a WordPress website, surfaced through the
`ListWordPressSecurity` endpoint and usable directly as `Test-CippWordPressSecurity -Url <site>`.

## Before you scan

Scan only sites you own or are engaged to assess. The requests are ordinary GETs and nothing here
can damage a site, but pointing a scanner at a third party's website without permission is still
unauthorised scanning in most jurisdictions, including under the Dutch Wet computercriminaliteit
and the UK Computer Misuse Act. The endpoint writes an entry to the CIPP log naming the caller and
the target before the scan runs, so there is always a record of who asked for what.

## What it checks

| Area | Checks |
| --- | --- |
| Transport | HTTPS in use, HTTP redirects to HTTPS, certificate validity, expiry, hostname match, key size, negotiated TLS version, mixed content |
| Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookie `Secure` and `HttpOnly` flags, version banners, PHP branch against the support calendar |
| WordPress | Core version detection and comparison against the current release, version disclosure, PHP errors printed to visitors |
| Components | Plugin and theme inventory from enqueued assets, each compared against its WordPress.org release |
| Exposure | `wp-config` backups, `.env`, `.git`, debug logs, `readme.html`, the installer, directory listings, XML-RPC, `wp-cron.php` |
| Enumeration | Account names via the REST API and via author archives |

Findings carry a severity, an evidence string naming what was observed, and a recommendation. The
report is scored out of 100 and graded A-F, weighted so that one critical finding outranks any
number of small ones.

## What it deliberately does not do

- **No intrusive testing.** No form is submitted, no password is tried, nothing is uploaded, and no
  input is crafted to provoke an error. That is what makes the scan safe to run against a live
  customer site during business hours, and it is also the limit: this finds misconfiguration and
  missing patches, not logic flaws.
- **No vulnerability database.** Components are compared against their current release, not against
  CVE data. A component that is current is reported as current, not as safe. Pairing the inventory
  this produces with a vulnerability feed is the natural next step.
- **No authenticated checks.** Everything is seen from an anonymous visitor's position, so user
  roles, file permissions and database contents are out of view.

A clean report is evidence of good hygiene. It is not proof that a site cannot be compromised, and
it should be presented to customers that way.

## Safety of the scanner itself

The endpoint takes a URL from the caller and makes the function app fetch it, so the target is
resolved and pinned to the public internet before any request is made: loopback, private,
link-local (including the `169.254.169.254` instance metadata endpoint), carrier-grade NAT and
reserved ranges are all refused, as are non-HTTP schemes, non-default ports and credentials in the
URL. Redirects are re-checked against the same guard, so an open redirect on a customer's site
cannot be used to steer the scan back into the hosting network.

Each scan is capped at 30 requests by default. Checks that do not fit within the budget are
reported as `Unknown`, never as passes.

## Layout

| File | Role |
| --- | --- |
| `Test-CippWordPressSecurity.ps1` | Orchestrator: validates the target, runs the checks, scores the result |
| `Test-CippWordPressTarget.ps1`, `Get-CippPrivateAddressReason.ps1`, `Resolve-CippHostAddress.ps1` | The SSRF guard |
| `Invoke-CippWordPressProbe.ps1` | The single read-only request every check goes through |
| `Get-CippWordPressFingerprint.ps1`, `Get-CippWordPressAsset.ps1` | Detection of WordPress, its version, plugins and themes |
| `Test-CippWebSecurityHeader.ps1`, `Test-CippPhpVersionHeader.ps1` | Response header checks |
| `Test-CippWordPressExposure.ps1` | Path probes, XML-RPC and account enumeration |
| `Test-CippWordPressComponent.ps1`, `Get-CippWordPressLatestVersion.ps1`, `Compare-CippWordPressVersion.ps1` | Version currency |
| `Get-CippTlsCertificateInfo.ps1`, `Get-CippCertificateFinding.ps1` | TLS handshake and its findings |
| `New-CippWordPressFinding.ps1`, `Get-CippWordPressRiskScore.ps1` | Finding shape and scoring |

Tests live in `Tests/Private/*CippWordPress*.Tests.ps1`, `Tests/Private/Test-CippWebSecurityHeader.Tests.ps1`
and `Tests/Endpoint/Invoke-ListWordPressSecurity.Tests.ps1`.
