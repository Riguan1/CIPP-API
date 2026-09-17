"""Response header checks.

Pure inspection of one response: no request is made here, so the same headers always produce the
same findings and the checks can be tested against captured responses.

The checks are deliberately conservative about what counts as a failure. A header that is present
but weak is a warning, and a missing Content-Security-Policy is a warning even though it is the
strongest anti-XSS measure available -- retrofitting a CSP onto an existing WordPress theme is real
work, and a policy that breaks a customer's checkout is worse than no policy.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Finding, Severity, Status
from ..probe import ProbeResponse
from ..versions import compare_versions

#: End of security support per php.net. A branch newer than everything here is treated as current.
PHP_END_OF_LIFE = {
    "5.6": "2018-12-31",
    "7.0": "2019-01-10",
    "7.1": "2019-12-01",
    "7.2": "2020-11-30",
    "7.3": "2021-12-06",
    "7.4": "2022-11-28",
    "8.0": "2023-11-26",
    "8.1": "2025-12-31",
    "8.2": "2026-12-31",
    "8.3": "2027-12-31",
    "8.4": "2028-12-31",
}

HSTS_MINIMUM = 15552000  # 180 days

_PHP_VERSION = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


def check_headers(response: ProbeResponse, *, is_https: bool, now: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    header = response.header

    if is_https:
        findings.extend(_check_hsts(header("Strict-Transport-Security")))

    csp = header("Content-Security-Policy")
    findings.append(_check_framing(header("X-Frame-Options"), csp))
    findings.append(_check_nosniff(header("X-Content-Type-Options")))
    findings.append(_check_referrer_policy(header("Referrer-Policy")))
    findings.append(_check_csp(csp))
    findings.extend(_check_banners(header("Server"), header("X-Powered-By")))

    php_finding = check_php_version(header("Server"), header("X-Powered-By"), now=now)
    if php_finding:
        findings.append(php_finding)

    if is_https:
        findings.extend(_check_cookies(response.set_cookie))

    return findings


def _check_hsts(value: str | None) -> list[Finding]:
    if not value or not value.strip():
        return [
            Finding(
                id="WEB-HSTS-MISSING",
                category="Headers",
                title="HSTS is not enabled",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                evidence="No Strict-Transport-Security response header.",
                recommendation=(
                    "Send Strict-Transport-Security with a max-age of at least 15552000 (180 days). "
                    "Without it a visitor's first request can still be intercepted over plain HTTP."
                ),
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
            )
        ]

    match = _MAX_AGE.search(value)
    max_age = int(match.group(1)) if match else 0
    if max_age < HSTS_MINIMUM:
        return [
            Finding(
                id="WEB-HSTS-SHORT",
                category="Headers",
                title="HSTS max-age is short",
                severity=Severity.LOW,
                status=Status.WARN,
                evidence=f"Strict-Transport-Security: {value}",
                recommendation=(
                    "Raise max-age to at least 15552000 (180 days) once you are confident every "
                    "hostname serves HTTPS."
                ),
            )
        ]

    return [
        Finding(
            id="WEB-HSTS-MISSING",
            category="Headers",
            title="HSTS is enabled",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            evidence=f"Strict-Transport-Security: {value}",
        )
    ]


def _check_framing(frame_options: str | None, csp: str | None) -> Finding:
    has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
    if not frame_options and not has_frame_ancestors:
        return Finding(
            id="WEB-CLICKJACKING",
            category="Headers",
            title="The site can be framed by any other site",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            evidence="Neither X-Frame-Options nor a CSP frame-ancestors directive was sent.",
            recommendation=(
                "Send X-Frame-Options: SAMEORIGIN, or a Content-Security-Policy with "
                "frame-ancestors 'self'. This is what stops an attacker overlaying your admin "
                "pages inside their own page."
            ),
            reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
        )

    evidence = (
        f"X-Frame-Options: {frame_options}" if frame_options else "CSP frame-ancestors directive present."
    )
    return Finding(
        id="WEB-CLICKJACKING",
        category="Headers",
        title="Framing is restricted",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        evidence=evidence,
    )


def _check_nosniff(value: str | None) -> Finding:
    if value and "nosniff" in value.lower():
        return Finding(
            id="WEB-NOSNIFF",
            category="Headers",
            title="MIME sniffing is disabled",
            severity=Severity.LOW,
            status=Status.PASS,
            evidence=f"X-Content-Type-Options: {value}",
        )
    return Finding(
        id="WEB-NOSNIFF",
        category="Headers",
        title="MIME sniffing is not disabled",
        severity=Severity.LOW,
        status=Status.FAIL,
        evidence="No X-Content-Type-Options: nosniff header.",
        recommendation=(
            "Send X-Content-Type-Options: nosniff so an uploaded file cannot be re-interpreted by "
            "the browser as script."
        ),
    )


def _check_referrer_policy(value: str | None) -> Finding:
    if value and value.strip():
        return Finding(
            id="WEB-REFERRER-POLICY",
            category="Headers",
            title="A Referrer-Policy is set",
            severity=Severity.LOW,
            status=Status.PASS,
            evidence=f"Referrer-Policy: {value}",
        )
    return Finding(
        id="WEB-REFERRER-POLICY",
        category="Headers",
        title="No Referrer-Policy is set",
        severity=Severity.LOW,
        status=Status.FAIL,
        evidence="No Referrer-Policy response header.",
        recommendation=(
            "Send Referrer-Policy: strict-origin-when-cross-origin so query strings and admin "
            "paths are not leaked to third-party sites."
        ),
    )


def _check_csp(value: str | None) -> Finding:
    if not value or not value.strip():
        return Finding(
            id="WEB-CSP-MISSING",
            category="Headers",
            title="No Content-Security-Policy",
            severity=Severity.MEDIUM,
            status=Status.WARN,
            evidence="No Content-Security-Policy response header.",
            recommendation=(
                "Consider a Content-Security-Policy. It is the strongest defence against "
                "cross-site scripting, but it needs testing against the theme and plugins first - "
                "start in report-only mode."
            ),
            reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
        )

    lowered = value.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return Finding(
            id="WEB-CSP-WEAK",
            category="Headers",
            title="The Content-Security-Policy allows inline script",
            severity=Severity.LOW,
            status=Status.WARN,
            evidence=f"Content-Security-Policy: {value}",
            recommendation=(
                "unsafe-inline and unsafe-eval remove most of the XSS protection a CSP provides. "
                "Move to nonces or hashes for the scripts that need it."
            ),
        )

    return Finding(
        id="WEB-CSP-MISSING",
        category="Headers",
        title="A Content-Security-Policy is set",
        severity=Severity.MEDIUM,
        status=Status.PASS,
        evidence=f"Content-Security-Policy: {value}",
    )


def _check_banners(server: str | None, powered_by: str | None) -> list[Finding]:
    findings = []
    for name, value in (("Server", server), ("X-Powered-By", powered_by)):
        if not value or not re.search(r"\d+\.\d+", value):
            continue
        findings.append(
            Finding(
                id=f"WEB-BANNER-{name.upper()}",
                category="Headers",
                title=f"The {name} header discloses software versions",
                severity=Severity.LOW,
                status=Status.FAIL,
                evidence=f"{name}: {value}",
                recommendation=(
                    f"Trim the {name} header to the product name. Exact versions let an attacker "
                    "match your server against a list of known vulnerabilities without touching "
                    "the site."
                ),
            )
        )
    return findings


def check_php_version(
    server: str | None, powered_by: str | None, *, now: datetime | None = None
) -> Finding | None:
    """Judge a disclosed PHP version against the support calendar.

    Compared against the current date rather than baked into a verdict, so this keeps giving the
    right answer as branches age without anyone remembering to edit it.
    """
    version = None
    for candidate in (powered_by, server):
        if not candidate:
            continue
        match = _PHP_VERSION.search(candidate)
        if match:
            version = match.group(1)
            break
    if not version:
        return None

    now = now or datetime.now(timezone.utc)
    branch = ".".join(version.split(".")[:2])

    if branch not in PHP_END_OF_LIFE:
        # Older than every branch in the table (PHP 5.5 and down) rather than newer.
        if compare_versions(branch, "5.6") < 0:
            return Finding(
                id="WEB-PHP-EOL",
                category="Headers",
                title=f"PHP {version} is long out of support",
                severity=Severity.HIGH,
                status=Status.FAIL,
                evidence=f"The server reports PHP {version}.",
                recommendation=(
                    "Move the site to a supported PHP branch. This version stopped receiving "
                    "security fixes years ago."
                ),
                reference="https://www.php.net/supported-versions.php",
            )
        return None

    eol = datetime.fromisoformat(PHP_END_OF_LIFE[branch]).replace(tzinfo=timezone.utc)

    if now > eol:
        return Finding(
            id="WEB-PHP-EOL",
            category="Headers",
            title=f"PHP {version} no longer receives security fixes",
            severity=Severity.HIGH,
            status=Status.FAIL,
            evidence=(
                f"The server reports PHP {version}; security support for the {branch} branch "
                f"ended on {eol.date()}."
            ),
            recommendation=(
                "Ask the hosting provider to move the site to a supported PHP branch, after "
                "testing the theme and plugins against it."
            ),
            reference="https://www.php.net/supported-versions.php",
        )

    if (eol - now).days <= 120:
        return Finding(
            id="WEB-PHP-EOL",
            category="Headers",
            title=f"PHP {version} reaches end of support soon",
            severity=Severity.MEDIUM,
            status=Status.WARN,
            evidence=(
                f"The server reports PHP {version}; security support for the {branch} branch "
                f"ends on {eol.date()}."
            ),
            recommendation=(
                "Plan the PHP upgrade now, while it is still routine maintenance rather than an "
                "emergency."
            ),
            reference="https://www.php.net/supported-versions.php",
        )

    return Finding(
        id="WEB-PHP-EOL",
        category="Headers",
        title=f"PHP {version} is supported",
        severity=Severity.HIGH,
        status=Status.PASS,
        evidence=(
            f"The server reports PHP {version}; the {branch} branch is supported until {eol.date()}."
        ),
    )


def _check_cookies(set_cookie: list[str]) -> list[Finding]:
    """Judge cookie flags, but only on HTTPS.

    On a plaintext site the missing transport is the finding; marking cookies Secure there would
    break the site without fixing anything.
    """
    if not set_cookie:
        return []

    insecure, no_httponly = [], []
    for cookie in set_cookie:
        name = cookie.split("=", 1)[0].strip()
        if not name:
            continue
        attributes = [part.strip().lower() for part in cookie.split(";")[1:]]
        if "secure" not in attributes:
            insecure.append(name)
        if "httponly" not in attributes:
            no_httponly.append(name)

    findings = []
    if insecure:
        findings.append(
            Finding(
                id="WEB-COOKIE-SECURE",
                category="Headers",
                title="Cookies are set without the Secure flag",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                evidence=f"Set without Secure: {', '.join(insecure)}",
                recommendation=(
                    "Set the Secure flag on every cookie on an HTTPS site, so the browser never "
                    "sends it over a plaintext connection."
                ),
            )
        )
    if no_httponly:
        findings.append(
            Finding(
                id="WEB-COOKIE-HTTPONLY",
                category="Headers",
                title="Cookies are readable by JavaScript",
                severity=Severity.LOW,
                status=Status.WARN,
                evidence=f"Set without HttpOnly: {', '.join(no_httponly)}",
                recommendation=(
                    "Set HttpOnly on session cookies so a cross-site scripting bug cannot read "
                    "them. Cookies a theme or plugin reads in the browser on purpose are the "
                    "exception."
                ),
            )
        )
    if not findings:
        findings.append(
            Finding(
                id="WEB-COOKIE-SECURE",
                category="Headers",
                title="Cookies carry the Secure and HttpOnly flags",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                evidence=f"{len(set_cookie)} cookie(s) checked.",
            )
        )
    return findings
