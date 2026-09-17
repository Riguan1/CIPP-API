"""Paths a WordPress site most often leaves reachable, and what answered.

Every probe is a plain GET for a path an anonymous visitor could request anyway. Nothing is
submitted, no password is tried, and no parameter is crafted to provoke an error. That is what
makes it safe to run against a live customer site during business hours -- and it is also the
limit: an issue that only an authenticated or intrusive test would find is out of reach here.

A 200 response is never treated as proof on its own. Plenty of WordPress installs answer every
unknown path with a themed 404 page carrying status 200, so a random path is requested first to
establish that behaviour and each probe additionally requires content matching the file it is
looking for. A wp-config backup is only reported when the response really does contain database
constants -- the alternative is an MSP rotating a customer's database credentials over a 404 page.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..models import Component, Finding, Severity, Status
from ..probe import Prober

ROTATE = (
    "Delete it from the web root today and rotate the database password, the WordPress salts and "
    "any API keys it contained."
)


@dataclass
class FileProbe:
    path: str
    id: str
    signature: str
    severity: Severity
    title: str
    recommendation: str


FILE_PROBES = [
    FileProbe(
        "wp-config.php.bak",
        "WP-CONFIG-BACKUP",
        r"DB_PASSWORD|DB_NAME|DB_USER",
        Severity.CRITICAL,
        "A wp-config backup is downloadable",
        ROTATE + " Anyone who has fetched this file has your database credentials.",
    ),
    FileProbe(
        "wp-config.php.save",
        "WP-CONFIG-BACKUP",
        r"DB_PASSWORD|DB_NAME|DB_USER",
        Severity.CRITICAL,
        "A wp-config backup is downloadable",
        ROTATE,
    ),
    FileProbe(
        "wp-config.php.old",
        "WP-CONFIG-BACKUP",
        r"DB_PASSWORD|DB_NAME|DB_USER",
        Severity.CRITICAL,
        "A wp-config backup is downloadable",
        ROTATE,
    ),
    FileProbe(
        "wp-config.txt",
        "WP-CONFIG-BACKUP",
        r"DB_PASSWORD|DB_NAME|DB_USER",
        Severity.CRITICAL,
        "A wp-config backup is downloadable",
        ROTATE,
    ),
    FileProbe(
        ".env",
        "WP-ENV-FILE",
        r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=",
        Severity.CRITICAL,
        "An .env file is downloadable",
        "Move it outside the web root and rotate every secret it holds. .env files routinely carry "
        "database, mail and payment credentials.",
    ),
    FileProbe(
        ".git/config",
        "WP-GIT-EXPOSED",
        r"\[core\]|repositoryformatversion",
        Severity.HIGH,
        "The .git directory is served to visitors",
        "Block /.git in the web server configuration. A published repository lets anyone "
        "reconstruct your source, and its history often still contains credentials that were "
        "removed later.",
    ),
    FileProbe(
        "wp-content/debug.log",
        "WP-DEBUG-LOG",
        r"PHP (Notice|Warning|Fatal error|Deprecated)|Stack trace",
        Severity.HIGH,
        "The WordPress debug log is downloadable",
        "Set WP_DEBUG_LOG to false in wp-config.php and delete the file. Debug logs disclose "
        "absolute paths, queries and sometimes session data.",
    ),
    FileProbe(
        "readme.html",
        "WP-README",
        r"WordPress",
        Severity.LOW,
        "readme.html is reachable and names the WordPress version",
        "Delete readme.html after each update. It hands an attacker your exact version without "
        "them having to fingerprint anything.",
    ),
    FileProbe(
        "wp-admin/install.php",
        "WP-INSTALLER",
        r"weblog_title|famous five-minute WordPress installation",
        Severity.CRITICAL,
        "The WordPress installer is reachable",
        "This lets anyone reinstall the site and take ownership of it. Complete or remove the "
        "installation immediately.",
    ),
    FileProbe(
        "wp-content/uploads/",
        "WP-DIRECTORY-LISTING",
        r"Index of /|<title>Index of",
        Severity.MEDIUM,
        "The uploads directory lists its contents",
        "Disable directory indexing (Options -Indexes on Apache, autoindex off on nginx). A "
        "listing exposes documents that were uploaded but never linked.",
    ),
    FileProbe(
        "wp-content/plugins/",
        "WP-DIRECTORY-LISTING-PLUGINS",
        r"Index of /|<title>Index of",
        Severity.MEDIUM,
        "The plugins directory lists its contents",
        "Disable directory indexing. The listing gives an attacker the full plugin inventory, "
        "including plugins that are installed but deactivated.",
    ),
]


@dataclass
class ExposureResult:
    findings: list[Finding] = field(default_factory=list)
    soft_not_found: bool = False


def check_exposure(prober: Prober, base_url: str) -> ExposureResult:
    result = ExposureResult()
    findings = result.findings

    def probe(path: str):
        if prober.budget_left <= 0:
            return None
        return prober.get(urljoin(base_url, path))

    # A path that cannot exist. If the site answers it with 200, status alone proves nothing and
    # every probe below has to rely on its content signature.
    baseline_path = f"wp-audit-{uuid.uuid4().hex[:12]}"
    baseline = probe(baseline_path)
    result.soft_not_found = bool(baseline and baseline.ok and baseline.status_code == 200)

    if result.soft_not_found:
        findings.append(
            Finding(
                id="WP-SOFT-404",
                category="Exposure",
                title="The site answers unknown URLs with 200 OK",
                severity=Severity.INFO,
                status=Status.INFO,
                evidence=f"A request for /{baseline_path} returned 200 instead of 404.",
                recommendation=(
                    "Not a vulnerability, but it hides missing pages from monitoring and from "
                    "scanners. Findings below were confirmed on response content rather than "
                    "status code."
                ),
            )
        )

    for file_probe in FILE_PROBES:
        if prober.budget_left <= 0:
            findings.append(
                Finding(
                    id=file_probe.id,
                    category="Exposure",
                    title=file_probe.title,
                    severity=file_probe.severity,
                    status=Status.UNKNOWN,
                    evidence="Not checked: the scan reached its request limit.",
                    recommendation="Re-run with a higher request limit to check this.",
                )
            )
            continue

        response = probe(file_probe.path)
        if not response or not response.ok:
            continue

        matched = response.status_code == 200 and re.search(
            file_probe.signature, response.text, re.IGNORECASE
        )
        if matched:
            findings.append(
                Finding(
                    id=file_probe.id,
                    category="Exposure",
                    title=file_probe.title,
                    severity=file_probe.severity,
                    status=Status.FAIL,
                    evidence=f"{response.final_url} returned {response.status_code} with matching content.",
                    recommendation=file_probe.recommendation,
                )
            )
        elif (
            response.status_code == 200
            and file_probe.severity is Severity.CRITICAL
            and not result.soft_not_found
        ):
            # 200 on a path that should not exist, but the content is not what the file would
            # contain. Worth a human look rather than a pass, given what these files hold.
            findings.append(
                Finding(
                    id=file_probe.id,
                    category="Exposure",
                    title=file_probe.title,
                    severity=file_probe.severity,
                    status=Status.UNKNOWN,
                    evidence=f"{response.final_url} returned 200 but the response did not look like the file itself.",
                    recommendation="Open the URL to confirm what is being served there.",
                )
            )

    findings.extend(_check_xmlrpc(probe))
    findings.extend(_check_rest_users(probe))
    findings.extend(_check_author_enumeration(probe))
    findings.extend(_check_login(probe))
    findings.extend(_check_wp_cron(probe))
    return result


def _check_xmlrpc(probe) -> list[Finding]:
    response = probe("xmlrpc.php")
    if not response or not response.ok:
        return []
    # WordPress answers a GET with 405 and this exact sentence when the endpoint is live.
    enabled = "XML-RPC server accepts POST requests only" in response.text or (
        response.status_code == 405 and "XML-RPC" in response.text
    )
    if enabled:
        return [
            Finding(
                id="WP-XMLRPC",
                category="Exposure",
                title="XML-RPC is enabled",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                evidence=f"{response.final_url} returned {response.status_code}: XML-RPC server accepts POST requests only.",
                recommendation=(
                    "Block xmlrpc.php unless Jetpack or the WordPress mobile app needs it. It "
                    "allows hundreds of password guesses in a single request through "
                    "system.multicall, and its pingback method can be abused to attack other sites "
                    "from yours."
                ),
                reference="https://developer.wordpress.org/apis/xml-rpc/",
            )
        ]
    return [
        Finding(
            id="WP-XMLRPC",
            category="Exposure",
            title="XML-RPC is not reachable",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            evidence=f"{response.final_url} returned {response.status_code}.",
        )
    ]


def _check_rest_users(probe) -> list[Finding]:
    response = probe("wp-json/wp/v2/users")
    if not response or not response.ok:
        return []
    if response.status_code == 200 and re.search(r'"slug"\s*:', response.text):
        names = list(dict.fromkeys(re.findall(r'"slug"\s*:\s*"([^"]+)"', response.text)))
        shown = ", ".join(names[:5])
        evidence = f"{response.final_url} listed {len(names)} account name(s)"
        if shown:
            evidence += f": {shown}"
        return [
            Finding(
                id="WP-REST-USERS",
                category="Enumeration",
                title="The REST API lists account names",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                evidence=evidence,
                recommendation=(
                    "Restrict /wp-json/wp/v2/users to authenticated requests. Usernames are half "
                    "of a password-guessing attack, and this endpoint hands over the whole list "
                    "including administrators."
                ),
                reference="https://developer.wordpress.org/rest-api/reference/users/",
            )
        ]
    return [
        Finding(
            id="WP-REST-USERS",
            category="Enumeration",
            title="The REST API does not list account names",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            evidence=f"{response.final_url} returned {response.status_code}.",
        )
    ]


def _check_author_enumeration(probe) -> list[Finding]:
    response = probe("?author=1")
    if not response or not response.ok:
        return []
    match = re.search(r"/author/([^/?#]+)", response.final_url or "")
    if match:
        return [
            Finding(
                id="WP-AUTHOR-ENUM",
                category="Enumeration",
                title="Author archives disclose the login name",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                evidence=f"?author=1 redirected to {response.final_url}, disclosing '{match.group(1)}'.",
                recommendation=(
                    "Block ?author= requests, or set each user's nickname and display name to "
                    "something other than their login name so the archive slug stops matching it."
                ),
            )
        ]
    return [
        Finding(
            id="WP-AUTHOR-ENUM",
            category="Enumeration",
            title="Author archives do not disclose a login name",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            evidence=f"?author=1 returned {response.status_code} without redirecting to an author slug.",
        )
    ]


def _check_login(probe) -> list[Finding]:
    response = probe("wp-login.php")
    if not response or not response.ok:
        return []
    if response.status_code == 200 and re.search(r"user_login|wp-submit", response.text):
        return [
            Finding(
                id="WP-LOGIN-EXPOSED",
                category="Exposure",
                title="The login page is reachable from anywhere",
                severity=Severity.LOW,
                status=Status.INFO,
                evidence=f"{response.final_url} serves the standard WordPress login form.",
                recommendation=(
                    "Normal for most sites, and worth hardening: require MFA for every account, "
                    "add login rate limiting, and restrict wp-admin and wp-login.php by IP address "
                    "where the customer works from fixed locations."
                ),
            )
        ]
    return []


def _check_wp_cron(probe) -> list[Finding]:
    response = probe("wp-cron.php")
    if not response or not response.ok or response.status_code not in (200, 204):
        return []
    return [
        Finding(
            id="WP-CRON-EXPOSED",
            category="Exposure",
            title="wp-cron.php can be triggered by anyone",
            severity=Severity.LOW,
            status=Status.WARN,
            evidence=f"{response.final_url} returned {response.status_code}.",
            recommendation=(
                "Set DISABLE_WP_CRON to true in wp-config.php and run wp-cron from a real "
                "scheduled task. Left open, it is an easy way to load the server by requesting it "
                "repeatedly."
            ),
        )
    ]


_STABLE_TAG = re.compile(r"(?im)^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-]*)\s*$")
_README_VERSION = re.compile(r"(?im)^\s*Version:\s*([0-9][0-9A-Za-z.\-]*)\s*$")


def confirm_components(prober: Prober, base_url: str, components: list[Component]) -> int:
    """Read each component's readme.txt to confirm it is installed and pin its version.

    This exists because the version in an asset URL is the weakest link in the whole chain: an
    optimiser that strips `?ver=` leaves a component with no version, and a component with no
    version cannot be matched against any vulnerability feed. `readme.txt` is a static file
    WordPress.org requires plugins to ship, it is world-readable by default, and its `Stable tag`
    is the authoritative version.

    Costs one request per component, so the caller decides when it is worth spending.
    """
    confirmed = 0
    for component in components:
        if prober.budget_left <= 0:
            break
        kind = "plugins" if component.kind == "plugin" else "themes"
        response = prober.get(urljoin(base_url, f"wp-content/{kind}/{component.slug}/readme.txt"))
        if not response.ok or response.status_code != 200:
            continue
        match = _STABLE_TAG.search(response.text) or _README_VERSION.search(response.text)
        if not match:
            continue
        version = match.group(1)
        if version.lower() == "trunk":
            continue
        component.version = version
        component.evidence = f"{response.final_url} (Stable tag: {version})"
        confirmed += 1
    return confirmed
