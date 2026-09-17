"""Where the vulnerability data comes from.

Two sources, deliberately different in kind:

**Wordfence Intelligence** publishes its whole WordPress vulnerability database as one JSON
document, free and without an API key, under CC BY-SA 4.0. That is the default here because it can
be downloaded once and matched locally: scanning fifty sites with thirty plugins each costs one
HTTP request, not fifteen hundred, and it works offline afterwards. Attribution is a licence
condition, so the report carries it.

**WPScan** is the other well-known database. It is per-component rather than bulk (one request per
plugin) and needs an API token, whose free tier is 25 requests a day -- enough to enrich a single
site, not to sweep a customer base. It is supported as an optional second opinion for people who
already pay for it.

Neither feed is reachable from every network, and neither is guaranteed to be complete. A component
with no advisories means "nothing published in this feed for this version", not "safe".
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

import requests

WORDFENCE_SCANNER_FEED = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner"
WORDFENCE_PRODUCTION_FEED = (
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
)
WORDFENCE_ATTRIBUTION = (
    "Vulnerability data from Wordfence Intelligence (https://www.wordfence.com/threat-intel/), "
    "licensed CC BY-SA 4.0."
)
WPSCAN_API = "https://wpscan.com/api/v3"

USER_AGENT = "wp-audit/1.0 (+https://github.com/wp-audit)"


@dataclass
class VulnRecord:
    """One published vulnerability, narrowed to one affected version range of one component.

    A single advisory covering three plugins across two version ranges becomes several records.
    That denormalisation is what lets matching be a plain indexed lookup plus a range comparison,
    with no feed-specific logic left at scan time.
    """

    source: str
    vuln_id: str
    software_type: str  # core | plugin | theme
    slug: str
    title: str = ""
    cve: str | None = None
    cvss_score: float | None = None
    cvss_rating: str | None = None
    published: str | None = None
    references: list[str] = field(default_factory=list)
    patched: bool = False
    patched_versions: list[str] = field(default_factory=list)
    from_version: str | None = "*"
    from_inclusive: bool = True
    to_version: str | None = "*"
    to_inclusive: bool = True

    @property
    def patched_in(self) -> str | None:
        return self.patched_versions[0] if self.patched_versions else None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalise_type(value: str) -> str:
    value = (value or "").strip().lower()
    if value in ("core", "wordpress"):
        return "core"
    if value in ("plugin", "plugins"):
        return "plugin"
    if value in ("theme", "themes"):
        return "theme"
    return value or "unknown"


class WordfenceSource:
    """The bulk feed: one download, then everything is matched locally."""

    name = "wordfence"
    attribution = WORDFENCE_ATTRIBUTION

    def __init__(self, url: str = WORDFENCE_SCANNER_FEED, *, timeout: float = 120.0) -> None:
        self.url = url
        self.timeout = timeout

    def fetch(self) -> Any:
        response = requests.get(
            self.url,
            timeout=self.timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()

    def records(self, payload: Any | None = None) -> Iterator[VulnRecord]:
        if payload is None:
            payload = self.fetch()
        yield from self.parse(payload)

    @classmethod
    def parse(cls, payload: Any) -> Iterator[VulnRecord]:
        """Turn a Wordfence feed into records.

        The feed is keyed by vulnerability id, but the production and scanner variants differ in
        the surrounding shape and Wordfence has changed it before, so a list is accepted too and
        anything unrecognised is skipped rather than aborting an entire update over one entry.
        """
        if isinstance(payload, dict):
            entries: Iterable[Any] = payload.values()
        elif isinstance(payload, list):
            entries = payload
        else:
            return

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            yield from cls._parse_entry(entry)

    @classmethod
    def _parse_entry(cls, entry: dict) -> Iterator[VulnRecord]:
        vuln_id = str(entry.get("id") or entry.get("uuid") or "").strip()
        if not vuln_id:
            return

        title = str(entry.get("title") or "").strip()
        cvss = entry.get("cvss") or {}
        cvss_score = _as_float(cvss.get("score")) if isinstance(cvss, dict) else None
        cvss_rating = cvss.get("rating") if isinstance(cvss, dict) else None

        cve = entry.get("cve")
        if isinstance(cve, list):
            cve = cve[0] if cve else None

        references = entry.get("references") or []
        if isinstance(references, dict):
            references = list(references.values())
        references = [str(r) for r in references if r][:10]

        published = entry.get("published") or entry.get("updated")

        for software in entry.get("software") or []:
            if not isinstance(software, dict):
                continue
            slug = str(software.get("slug") or software.get("name") or "").strip().lower()
            if not slug:
                continue
            software_type = _normalise_type(str(software.get("type") or ""))

            patched = bool(software.get("patched"))
            patched_versions = [str(v) for v in (software.get("patched_versions") or []) if v]

            affected = software.get("affected_versions") or {}
            if isinstance(affected, dict):
                ranges = list(affected.values())
            elif isinstance(affected, list):
                ranges = affected
            else:
                ranges = []

            if not ranges:
                # No range given: the advisory still names the component, so record it as
                # unbounded rather than dropping it. Matching will flag it for any version, which
                # is noisy but visible -- the alternative loses the advisory silently.
                ranges = [{}]

            for affected_range in ranges:
                if not isinstance(affected_range, dict):
                    continue
                yield VulnRecord(
                    source=cls.name,
                    vuln_id=vuln_id,
                    software_type=software_type,
                    slug=slug,
                    title=title,
                    cve=str(cve) if cve else None,
                    cvss_score=cvss_score,
                    cvss_rating=str(cvss_rating) if cvss_rating else None,
                    published=str(published) if published else None,
                    references=references,
                    patched=patched,
                    patched_versions=patched_versions,
                    from_version=affected_range.get("from_version", "*"),
                    from_inclusive=bool(affected_range.get("from_inclusive", True)),
                    to_version=affected_range.get("to_version", "*"),
                    to_inclusive=bool(affected_range.get("to_inclusive", True)),
                )


class WPScanSource:
    """Per-component lookups against the WPScan API.

    Used to enrich a single scan rather than to build a database: the free tier allows 25 requests
    a day and each component costs one, so the caller decides which components are worth spending
    the budget on.
    """

    name = "wpscan"
    attribution = "Vulnerability data from WPScan (https://wpscan.com/)."

    def __init__(self, token: str, *, timeout: float = 30.0, api: str = WPSCAN_API) -> None:
        if not token:
            raise ValueError("A WPScan API token is required.")
        self.token = token
        self.timeout = timeout
        self.api = api

    def _get(self, path: str) -> Any:
        response = requests.get(
            f"{self.api}/{path}",
            timeout=self.timeout,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Authorization": f"Token token={self.token}",
            },
        )
        if response.status_code == 404:
            return {}
        if response.status_code == 429:
            raise RuntimeError("WPScan API rate limit reached (the free tier allows 25 a day).")
        response.raise_for_status()
        return response.json()

    def lookup(self, software_type: str, slug: str, version: str | None = None) -> list[VulnRecord]:
        software_type = _normalise_type(software_type)
        if software_type == "core":
            if not version:
                return []
            payload = self._get(f"wordpresses/{version.replace('.', '')}")
        elif software_type == "theme":
            payload = self._get(f"themes/{slug}")
        else:
            payload = self._get(f"plugins/{slug}")
        return list(self.parse(payload, software_type, slug))

    @classmethod
    def parse(cls, payload: Any, software_type: str, slug: str) -> Iterator[VulnRecord]:
        """WPScan answers keyed by the slug (or version) that was asked for."""
        if not isinstance(payload, dict):
            return

        for key, body in payload.items():
            if not isinstance(body, dict):
                continue
            for vulnerability in body.get("vulnerabilities") or []:
                if not isinstance(vulnerability, dict):
                    continue
                references = vulnerability.get("references") or {}
                urls = [str(u) for u in (references.get("url") or [])][:10]
                cves = references.get("cve") or []
                cve = f"CVE-{cves[0]}" if cves and not str(cves[0]).startswith("CVE-") else (
                    str(cves[0]) if cves else None
                )
                fixed_in = vulnerability.get("fixed_in")
                cvss = vulnerability.get("cvss") or {}

                yield VulnRecord(
                    source=cls.name,
                    vuln_id=str(vulnerability.get("id") or ""),
                    software_type=software_type,
                    slug=slug or str(key).lower(),
                    title=str(vulnerability.get("title") or ""),
                    cve=cve,
                    cvss_score=_as_float(cvss.get("score")) if isinstance(cvss, dict) else None,
                    cvss_rating=None,
                    published=vulnerability.get("published_date"),
                    references=urls,
                    patched=bool(fixed_in),
                    patched_versions=[str(fixed_in)] if fixed_in else [],
                    # WPScan states the version a fix landed in, not a range: everything below it
                    # is affected, and the fixed version itself is not.
                    from_version="*",
                    from_inclusive=True,
                    to_version=str(fixed_in) if fixed_in else "*",
                    to_inclusive=not bool(fixed_in),
                )


def load_feed_file(path: str) -> Any:
    """Read a feed that was downloaded elsewhere, for air-gapped or rate-limited setups."""
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
