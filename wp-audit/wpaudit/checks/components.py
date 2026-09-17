"""Are core, the plugins and the themes on their current release?

Out-of-date components are what actually gets WordPress sites compromised: most incidents trace
back to a known vulnerability in a plugin that had a patch available. This compares what the site
serves against the current release published on WordPress.org.

Being current is not the same as being safe -- a vulnerability with no patch yet is invisible here,
which is what the vulnerability database in `checks.vulnerabilities` is for. The wording of every
finding keeps those two apart on purpose.
"""

from __future__ import annotations

from typing import Any

import requests

from ..models import Component, Finding, Severity, Status
from ..versions import compare_versions, major_of

CORE_VERSION_API = "https://api.wordpress.org/core/version-check/1.7/"
PLUGIN_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
THEME_API = "https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={slug}"

USER_AGENT = "wp-audit/1.0 (+https://github.com/wp-audit)"


class WordPressOrg:
    """Thin client for the public WordPress.org APIs.

    Answers are cached per process because the same plugin turns up on many of an MSP's customer
    sites, and they are identical for everyone -- nothing customer-specific passes through here.
    A failed lookup returns None and never raises: losing the comparison must degrade a scan, not
    fail it.
    """

    def __init__(self, *, timeout: float = 10.0, enabled: bool = True) -> None:
        self.timeout = timeout
        self.enabled = enabled
        self._cache: dict[tuple[str, str], Any] = {}

    def _get(self, url: str) -> Any:
        try:
            response = requests.get(
                url, timeout=self.timeout, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
            )
            response.raise_for_status()
            return response.json()
        except (requests.exceptions.RequestException, ValueError):
            return None

    def core_version(self) -> str | None:
        if not self.enabled:
            return None
        key = ("core", "")
        if key not in self._cache:
            payload = self._get(CORE_VERSION_API)
            version = None
            if isinstance(payload, dict):
                offers = payload.get("offers") or []
                # Offers are ordered newest first and include upgrades for older branches; the
                # 'upgrade' response type is the current release.
                for offer in offers:
                    if isinstance(offer, dict) and offer.get("response") in ("upgrade", "latest"):
                        version = offer.get("current")
                        break
                if version is None and offers and isinstance(offers[0], dict):
                    version = offers[0].get("current")
            self._cache[key] = str(version) if version else None
        return self._cache[key]

    def component_version(self, kind: str, slug: str) -> tuple[str | None, str]:
        """Return (version, status) where status is Found, NotInDirectory or Unknown."""
        if not self.enabled:
            return None, "Unknown"
        key = (kind, slug.lower())
        if key in self._cache:
            return self._cache[key]

        url = (THEME_API if kind == "theme" else PLUGIN_API).format(slug=slug)
        payload = self._get(url)
        if payload is None:
            result: tuple[str | None, str] = (None, "Unknown")
        elif isinstance(payload, dict) and payload.get("error"):
            # Both APIs answer a missing slug with 200 and an error body rather than a 404.
            result = (None, "NotInDirectory")
        elif isinstance(payload, dict) and payload.get("version"):
            result = (str(payload["version"]), "Found")
        else:
            result = (None, "Unknown")

        self._cache[key] = result
        return result


def check_core(version: str | None, latest: str | None, *, lookups_enabled: bool) -> list[Finding]:
    findings: list[Finding] = []

    if not version:
        return [
            Finding(
                id="WP-CORE-OUTDATED",
                category="WordPress",
                title="The WordPress version could not be determined",
                severity=Severity.HIGH,
                status=Status.UNKNOWN,
                evidence="No version was disclosed in the page markup, headers or asset URLs.",
                recommendation=(
                    "Good practice in itself - but it also means this scan cannot tell you whether "
                    "core is up to date, or match it against known vulnerabilities. Confirm from "
                    "the admin dashboard."
                ),
            )
        ]

    findings.append(
        Finding(
            id="WP-VERSION-DISCLOSED",
            category="WordPress",
            title="The WordPress version is published",
            severity=Severity.LOW,
            status=Status.WARN,
            evidence=f"Version {version} is readable from the site itself.",
            recommendation=(
                "Remove the generator meta tag and the version query string from asset URLs. "
                "Hiding the version does not fix anything by itself, but it stops your site "
                "matching a search for that exact version."
            ),
        )
    )

    if not latest:
        findings.append(
            Finding(
                id="WP-CORE-OUTDATED",
                category="WordPress",
                title="WordPress core version could not be compared",
                severity=Severity.HIGH,
                status=Status.UNKNOWN,
                evidence=(
                    f"Detected version {version}. "
                    + (
                        "The WordPress.org lookup was skipped."
                        if not lookups_enabled
                        else "The WordPress.org lookup failed."
                    )
                ),
                recommendation="Compare the version against the current WordPress release manually.",
            )
        )
        return findings

    if compare_versions(version, latest) < 0:
        # A whole major behind means missed security releases for a year or more, which is a
        # different conversation from being one patch release late.
        severity = (
            Severity.CRITICAL if major_of(version) != major_of(latest) else Severity.HIGH
        )
        findings.append(
            Finding(
                id="WP-CORE-OUTDATED",
                category="WordPress",
                title="WordPress core is out of date",
                severity=severity,
                status=Status.FAIL,
                evidence=f"The site reports WordPress {version}; the current release is {latest}.",
                recommendation=(
                    "Update WordPress core. Take a backup first, then update on a staging copy if "
                    "the site is business-critical. Turn on automatic updates for minor releases so "
                    "security fixes land without waiting for a maintenance window."
                ),
                reference="https://wordpress.org/download/releases/",
            )
        )
    else:
        findings.append(
            Finding(
                id="WP-CORE-OUTDATED",
                category="WordPress",
                title="WordPress core is current",
                severity=Severity.HIGH,
                status=Status.PASS,
                evidence=f"The site reports WordPress {version}; the current release is {latest}.",
            )
        )

    return findings


def check_components(components: list[Component], client: WordPressOrg) -> list[Finding]:
    """Fill in each component's current release and report the ones that are behind."""
    findings: list[Finding] = []

    for component in components:
        latest, status = client.component_version(component.kind, component.slug)
        component.latest_version = latest

        if status == "NotInDirectory":
            component.status = "NotInDirectory"
            findings.append(
                Finding(
                    id=f"WP-COMPONENT-UNLISTED-{component.slug.upper()}",
                    category="Components",
                    title=f"{component.kind.title()} '{component.slug}' is not in the WordPress.org directory",
                    severity=Severity.MEDIUM,
                    status=Status.UNKNOWN,
                    evidence=f"{component.evidence} - WordPress.org has no entry for '{component.slug}'.",
                    recommendation=(
                        "Usually a premium or custom component, which this check cannot version-"
                        "compare. Confirm that it is still supported and receiving updates - a "
                        "plugin also disappears from the directory when WordPress closes it for an "
                        "unpatched vulnerability."
                    ),
                )
            )
            continue

        if status != "Found" or not component.version:
            component.status = "Unknown"
            continue

        if compare_versions(component.version, latest) < 0:
            component.status = "Outdated"
            severity = (
                Severity.HIGH
                if major_of(component.version) != major_of(latest)
                else Severity.MEDIUM
            )
            findings.append(
                Finding(
                    id=f"WP-COMPONENT-OUTDATED-{component.slug.upper()}",
                    category="Components",
                    title=f"{component.kind.title()} '{component.slug}' is out of date",
                    severity=severity,
                    status=Status.FAIL,
                    evidence=(
                        f"Version {component.version} is in use; {latest} is current. "
                        f"Detected from {component.evidence}."
                    ),
                    recommendation=(
                        f"Update {component.slug} to {latest}. Outdated plugins are the single most "
                        "common way WordPress sites are compromised, because the fix being public "
                        "is what tells attackers what to look for."
                    ),
                    reference=f"https://wordpress.org/plugins/{component.slug}/",
                )
            )
        else:
            component.status = "Current"

    outdated = [c for c in components if c.status == "Outdated"]
    if components and not outdated and client.enabled:
        findings.append(
            Finding(
                id="WP-COMPONENTS-CURRENT",
                category="Components",
                title="Every detected plugin and theme is current",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                evidence=f"{len(components)} component(s) detected, none behind their published release.",
            )
        )

    return findings
