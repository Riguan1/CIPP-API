"""Checking a feed update against what your customers already run.

This is the question that makes a daily feed download worth anything: not "what is in the feed"
but "does today's feed contain something affecting a plugin one of my customers has installed".

Answering it does not need a single HTTP request. The scan history already knows which components
were seen on which site, so the check is the inventory matched against the database before the
update and again after it -- anything in the second set that was not in the first is news.

It also means a customer is covered between scans. A vulnerability published this morning in a
plugin that was scanned last week surfaces at the next feed update, not at the next scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .history import ScanHistory
from .models import VulnerabilityMatch
from .vulndb.store import VulnerabilityDatabase

CORE_SLUG = "wordpress"


@dataclass
class InventoryMatch:
    site: str
    kind: str
    slug: str
    version: str | None
    match: VulnerabilityMatch

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (self.site, self.kind, self.slug, self.match.source, self.match.vuln_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "kind": self.kind,
            "slug": self.slug,
            "version": self.version,
            **self.match.to_dict(),
        }


def match_inventory(database: VulnerabilityDatabase, history: ScanHistory) -> list[InventoryMatch]:
    """Every advisory in the database that covers a component version seen on a scanned site."""
    if not database.info().exists:
        return []

    matches: list[InventoryMatch] = []

    for site, version in history.cores():
        for match in database.match("core", CORE_SLUG, version):
            matches.append(
                InventoryMatch(site=site, kind="core", slug=CORE_SLUG, version=version, match=match)
            )

    for component in history.components():
        if not component.version:
            # No version, no match to make. It is reported as unmatched in the scan itself; there
            # is nothing new to say about it here.
            continue
        for match in database.match(component.kind, component.slug, component.version):
            matches.append(
                InventoryMatch(
                    site=component.site,
                    kind=component.kind,
                    slug=component.slug,
                    version=component.version,
                    match=match,
                )
            )

    return matches


def new_matches(
    before: list[InventoryMatch], after: list[InventoryMatch]
) -> list[InventoryMatch]:
    """Advisories that apply now and did not before the update.

    Sorted worst first: whoever reads a feed-update alert reads the top of it.
    """
    known = {match.key for match in before}
    fresh = [match for match in after if match.key not in known]
    return sorted(fresh, key=lambda m: (-(m.match.cvss_score or 0.0), m.site, m.slug))


def group_by_site(matches: list[InventoryMatch]) -> dict[str, list[InventoryMatch]]:
    grouped: dict[str, list[InventoryMatch]] = {}
    for match in matches:
        grouped.setdefault(match.site, []).append(match)
    return grouped


def render_feed_alert(matches: list[InventoryMatch], *, limit_per_site: int = 5) -> str:
    """The text a feed update prints, and mails, when it finds something."""
    if not matches:
        return ""

    grouped = group_by_site(matches)
    lines = [
        f"{len(matches)} new advisory match(es) against components already seen on "
        f"{len(grouped)} site(s):",
        "",
    ]
    for site in sorted(grouped):
        lines.append(f"  {site}")
        for entry in grouped[site][:limit_per_site]:
            match = entry.match
            parts = [f"{entry.slug} {entry.version or '?'}"]
            if match.cve:
                parts.append(match.cve)
            if match.cvss_score is not None:
                parts.append(f"CVSS {match.cvss_score}")
            if match.patched_in:
                parts.append(f"fixed in {match.patched_in}")
            lines.append(f"    - {' | '.join(parts)}")
            if match.title:
                lines.append(f"      {match.title}")
        if len(grouped[site]) > limit_per_site:
            lines.append(f"    ...and {len(grouped[site]) - limit_per_site} more")
        lines.append("")

    lines.append(
        "These are version matches against the sites' last known inventory. Re-scan to confirm "
        "the versions are still what is installed."
    )
    return "\n".join(lines)
