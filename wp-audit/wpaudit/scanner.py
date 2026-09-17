"""The scan itself: what runs, in what order, and what happens when a part of it cannot.

Order matters here. The target guard runs before any request is made; the home page decides which
host the rest of the scan reads (a site that redirects www to apex should be judged on the apex);
and the component inventory has to exist before vulnerability matching has anything to match.

Nothing in here raises on a site problem. A refused connection, a broken certificate and a missing
vulnerability database are all reported as results, because an MSP scanning fifty sites needs the
other forty-nine to finish.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .checks import components as components_check
from .checks import exposure as exposure_check
from .checks import headers as headers_check
from .checks import transport as transport_check
from .checks import vulnerabilities as vulnerabilities_check
from .fingerprint import fingerprint as run_fingerprint
from .models import Finding, ScanReport, Severity, Status
from .probe import Prober
from .scoring import score_findings, sort_findings
from .target import validate_target
from .vulndb.store import VulnerabilityDatabase

# PHP's own error format: "<level>: <message> in <file> on line <n>". With html_errors on -- the
# default -- each part is wrapped in tags, so a pattern anchored on "Warning:" matches nothing on a
# real site. Requiring the "in ... on line N" tail is what keeps ordinary prose from matching.
_PHP_ERROR = re.compile(
    r"\b(Fatal error|Parse error|Warning|Notice|Deprecated)\b\s*(?:</[a-z]+>)?\s*:"
    r".{0,300}?\bin\b.{0,200}?\bon line\b\s*(?:<[a-z]+>)?\s*\d+",
    re.IGNORECASE | re.DOTALL,
)
# The w3.org namespace URLs in SVG and XHTML markup are identifiers, not fetches.
_MIXED_CONTENT = re.compile(
    r"""(?:src|href)\s*=\s*["']http://(?!www\.w3\.org)([^"'\s]+)""", re.IGNORECASE
)


def scan(
    url: str,
    *,
    timeout: float = 15.0,
    max_requests: int = 30,
    skip_version_lookup: bool = False,
    skip_exposure: bool = False,
    confirm_components: bool = False,
    database: VulnerabilityDatabase | None = None,
    wordpress_org: components_check.WordPressOrg | None = None,
) -> ScanReport:
    report = ScanReport(url=url, scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    if skip_exposure:
        report.skipped.append("Exposure")
        report.skipped.append("Enumeration")
    if database is None:
        report.skipped.append("Vulnerabilities")

    target = validate_target(url)
    if not target.valid:
        report.error = target.reason
        return report

    findings: list[Finding] = []
    prober = Prober(timeout=timeout, max_requests=max_requests)

    try:
        home = prober.get(target.url)

        if home.certificate_error:
            findings.append(
                Finding(
                    id="WEB-TLS-INVALID",
                    category="Transport",
                    title="The TLS certificate is not trusted",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    evidence=f"The certificate presented by {target.host} failed validation.",
                    recommendation=(
                        "Fix or replace the certificate. Visitors are seeing a browser warning, and "
                        "a site people are trained to click through on is a site they will click "
                        "through on when the warning is real."
                    ),
                )
            )

        if not home.ok:
            report.error = f"The site could not be reached. {home.error}"
            report.findings = findings
            report.requests_made = prober.requests_made
            return report

        # Where the request came to rest is the site: it accounts for http-to-https upgrades and
        # for www redirects, and scanning the pre-redirect URL would check a host nobody visits.
        effective_url = home.final_url or target.url
        parts = urlsplit(effective_url)
        base_url = f"{parts.scheme}://{parts.netloc}/"
        report.final_url = effective_url
        is_https = parts.scheme == "https"

        findings.extend(_transport_findings(prober, parts, base_url, is_https, timeout, report))
        findings.extend(headers_check.check_headers(home, is_https=is_https))
        findings.extend(_content_findings(home.text, is_https))

        finger = run_fingerprint(home.text, home.headers, base_url)
        report.is_wordpress = finger.is_wordpress
        report.wordpress_version = finger.version

        if not finger.is_wordpress:
            findings.append(
                Finding(
                    id="WP-NOT-DETECTED",
                    category="WordPress",
                    title="This does not look like a WordPress site",
                    severity=Severity.INFO,
                    status=Status.INFO,
                    evidence="No WordPress markers were found in the home page or its headers.",
                    recommendation=(
                        "The transport and header findings still apply. If you expected WordPress "
                        "here, check whether the site is behind a cache or page builder that "
                        "rewrites its markup, or whether WordPress lives on a different path."
                    ),
                )
            )
        else:
            report.components = finger.components

            if confirm_components and report.components:
                # Worth the requests: a component with no version is invisible to vulnerability
                # matching, and readme.txt is the authoritative version.
                exposure_check.confirm_components(prober, base_url, report.components)

            if not skip_exposure:
                exposure = exposure_check.check_exposure(prober, base_url)
                findings.extend(exposure.findings)

            client = wordpress_org or components_check.WordPressOrg(enabled=not skip_version_lookup)
            latest_core = client.core_version()
            report.latest_wordpress_version = latest_core
            findings.extend(
                components_check.check_core(
                    finger.version, latest_core, lookups_enabled=client.enabled
                )
            )
            findings.extend(components_check.check_components(report.components, client))

            if database is not None:
                findings.extend(
                    vulnerabilities_check.check_vulnerabilities(
                        database, core_version=finger.version, components=report.components
                    )
                )
                report.vulnerability_db = database.info().to_dict()
    finally:
        report.requests_made = prober.requests_made
        prober.close()

    ordered = sort_findings(findings)
    risk = score_findings(ordered)
    report.findings = ordered
    report.score = risk.score
    report.grade = risk.grade
    report.summary = risk.summary
    report.completed = True
    return report


def _transport_findings(prober, parts, base_url, is_https, timeout, report) -> list[Finding]:
    findings: list[Finding] = []

    if not is_https:
        findings.append(
            Finding(
                id="WEB-HTTPS",
                category="Transport",
                title="The site is not served over HTTPS",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                evidence=f"{base_url} was served over plain HTTP.",
                recommendation=(
                    "Install a certificate and force HTTPS. Every password and session cookie on "
                    "this site currently crosses the network readable by anyone on the path, and "
                    "browsers mark it as insecure."
                ),
            )
        )
        return findings

    findings.append(
        Finding(
            id="WEB-HTTPS",
            category="Transport",
            title="The site is served over HTTPS",
            severity=Severity.HIGH,
            status=Status.PASS,
            evidence=base_url,
        )
    )

    if prober.budget_left > 0:
        plain_url = f"http://{parts.netloc}/"
        plain = prober.get(plain_url)
        if plain.ok and plain.final_url.startswith("https://"):
            findings.append(
                Finding(
                    id="WEB-HTTPS-REDIRECT",
                    category="Transport",
                    title="Plain HTTP redirects to HTTPS",
                    severity=Severity.MEDIUM,
                    status=Status.PASS,
                    evidence=f"{plain_url} redirects to {plain.final_url}.",
                )
            )
        elif plain.ok:
            findings.append(
                Finding(
                    id="WEB-HTTPS-REDIRECT",
                    category="Transport",
                    title="The site is also served over plain HTTP",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    evidence=f"{plain_url} returned {plain.status_code} without redirecting to HTTPS.",
                    recommendation=(
                        "Redirect every HTTP request to HTTPS permanently. Until you do, a login "
                        "submitted over the plaintext URL travels in the clear."
                    ),
                )
            )

    certificate = transport_check.inspect_certificate(parts.hostname, parts.port or 443, timeout)
    report.certificate = certificate.to_dict()
    findings.extend(transport_check.certificate_findings(certificate))
    return findings


def _content_findings(html: str, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []

    if is_https:
        mixed = _MIXED_CONTENT.findall(html or "")
        if mixed:
            sample = ", ".join("http://" + m for m in mixed[:3])
            findings.append(
                Finding(
                    id="WEB-MIXED-CONTENT",
                    category="Transport",
                    title="The page loads resources over plain HTTP",
                    severity=Severity.LOW,
                    status=Status.WARN,
                    evidence=f"{len(mixed)} HTTP reference(s) on an HTTPS page, including: {sample}",
                    recommendation=(
                        "Point these at their HTTPS equivalents. Browsers block or downgrade mixed "
                        "content, so this breaks parts of the page as well as weakening it."
                    ),
                )
            )

    if _PHP_ERROR.search(html or ""):
        findings.append(
            Finding(
                id="WP-PHP-ERRORS",
                category="Exposure",
                title="PHP errors are displayed to visitors",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                evidence="The home page contains a PHP error message naming a file and line number.",
                recommendation=(
                    "Set WP_DEBUG_DISPLAY to false and display_errors to Off. Error output "
                    "discloses absolute server paths and plugin internals, and it tells an "
                    "attacker exactly which code path they just broke."
                ),
            )
        )

    return findings
