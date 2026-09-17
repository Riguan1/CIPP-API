"""What changed since the last scan.

The point of a recurring scan is not the report, it is the delta. A hundred sites produce a
hundred reports nobody reads; "wp-config backup appeared on klant-a.nl, HSTS fixed on klant-b.nl"
is three lines somebody acts on.

Changes are reported in both directions on purpose. New problems are the alert, but resolved ones
are what an MSP shows the customer at the end of the month, and they are also how you notice that a
site was restored from an old backup -- a batch of findings coming back together says more than any
single one of them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Finding, ScanReport, Severity, Status


@dataclass
class Snapshot:
    """The parts of a scan a diff needs, from a live report or a stored one."""

    site: str
    scanned_at: str
    completed: bool
    score: int
    grade: str
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)
    vulnerabilities: dict[str, dict[str, Any]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    @classmethod
    def from_report(cls, report: ScanReport, site: str = "") -> Snapshot:
        return cls.from_dict(report.to_dict(), site)

    @classmethod
    def from_dict(cls, data: dict[str, Any], site: str = "") -> Snapshot:
        findings = {
            finding["id"]: {
                "status": finding.get("status"),
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "category": finding.get("category", ""),
                "evidence": finding.get("evidence", ""),
                "recommendation": finding.get("recommendation", ""),
            }
            for finding in data.get("findings", [])
        }

        # Keyed by component and advisory rather than by finding id, so "CVE-X on plugin Y" can be
        # reported as gone even when the plugin still has other advisories against it and its
        # finding therefore persists.
        vulnerabilities: dict[str, dict[str, Any]] = {}
        for component in data.get("components", []):
            for vulnerability in component.get("vulnerabilities", []):
                key = f"{component.get('kind')}/{component.get('slug')}/{vulnerability.get('vuln_id')}"
                vulnerabilities[key] = {
                    "component": component.get("slug"),
                    "kind": component.get("kind"),
                    "version": component.get("version"),
                    "title": vulnerability.get("title"),
                    "cve": vulnerability.get("cve"),
                    "cvss_score": vulnerability.get("cvss_score"),
                    "severity": vulnerability.get("severity"),
                    "patched_in": vulnerability.get("patched_in"),
                }

        return cls(
            site=site or data.get("final_url") or data.get("url", ""),
            scanned_at=data.get("scanned_at", ""),
            completed=bool(data.get("completed")),
            score=int(data.get("score") or 0),
            grade=data.get("grade", "F"),
            findings=findings,
            vulnerabilities=vulnerabilities,
            skipped=list(data.get("skipped") or []),
        )


@dataclass
class FindingChange:
    finding_id: str
    title: str
    severity: str
    previous_status: str | None
    current_status: str | None
    evidence: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "previous_status": self.previous_status,
            "current_status": self.current_status,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanDiff:
    site: str
    completed: bool = True
    first_scan: bool = False
    previous_at: str | None = None
    current_at: str = ""
    previous_score: int | None = None
    current_score: int = 0
    previous_grade: str | None = None
    current_grade: str = "F"
    regressions: list[FindingChange] = field(default_factory=list)
    improvements: list[FindingChange] = field(default_factory=list)
    new_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    resolved_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    became_unreachable: bool = False
    became_reachable: bool = False

    @property
    def score_delta(self) -> int | None:
        if self.previous_score is None:
            return None
        return self.current_score - self.previous_score

    @property
    def has_changes(self) -> bool:
        return bool(
            self.regressions
            or self.improvements
            or self.new_vulnerabilities
            or self.resolved_vulnerabilities
            or self.became_unreachable
            or self.became_reachable
        )

    @property
    def worst_new_severity(self) -> str | None:
        severities = [change.severity for change in self.regressions]
        severities += [v.get("severity") for v in self.new_vulnerabilities if v.get("severity")]
        if not severities:
            return None
        order = {s.value: s.rank for s in Severity}
        return min(severities, key=lambda s: order.get(s, 99))

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "completed": self.completed,
            "first_scan": self.first_scan,
            "previous_at": self.previous_at,
            "current_at": self.current_at,
            "previous_score": self.previous_score,
            "current_score": self.current_score,
            "previous_grade": self.previous_grade,
            "current_grade": self.current_grade,
            "score_delta": self.score_delta,
            "regressions": [c.to_dict() for c in self.regressions],
            "improvements": [c.to_dict() for c in self.improvements],
            "new_vulnerabilities": self.new_vulnerabilities,
            "resolved_vulnerabilities": self.resolved_vulnerabilities,
            "became_unreachable": self.became_unreachable,
            "became_reachable": self.became_reachable,
        }


#: Statuses that mean "there is something to do here".
_OPEN = {Status.FAIL.value, Status.WARN.value}
#: Statuses that mean the scanner looked and there was nothing to do. Deliberately excludes
#: UNKNOWN, which means it could not look.
_CLOSED = {Status.PASS.value, Status.INFO.value}


def _is_open(status: str | None) -> bool:
    return status in _OPEN


def _is_closed(status: str | None) -> bool:
    return status in _CLOSED


def compare(previous: dict[str, Any] | None, current: ScanReport, *, site: str = "") -> ScanDiff:
    """Diff a scan against the stored previous one.

    A finding that was never checked before, or is not checked now, is not a change: `UNKNOWN`
    means the scanner could not see it, and treating that as either an improvement or a regression
    would produce alerts every time a site is slow.
    """
    site = site or (current.final_url or current.url)
    now = Snapshot.from_report(current, site)

    if previous is None:
        return ScanDiff(
            site=site,
            completed=now.completed,
            first_scan=True,
            current_at=now.scanned_at,
            current_score=now.score,
            current_grade=now.grade,
        )

    before = Snapshot.from_dict(previous, site)

    diff = ScanDiff(
        site=site,
        completed=now.completed,
        previous_at=before.scanned_at,
        current_at=now.scanned_at,
        previous_score=before.score,
        current_score=now.score,
        previous_grade=before.grade,
        current_grade=now.grade,
        became_unreachable=before.completed and not now.completed,
        became_reachable=not before.completed and now.completed,
    )

    if not now.completed:
        # Nothing was observed, so nothing can be said to have changed beyond reachability.
        return diff

    for finding_id in sorted(set(before.findings) | set(now.findings)):
        was = before.findings.get(finding_id)
        is_now = now.findings.get(finding_id)
        was_open = _is_open(was["status"]) if was else False
        is_open = _is_open(is_now["status"]) if is_now else False

        # A check group that did not run this time cannot have fixed anything. Without this, a
        # scan with --skip-exposure reports every exposure finding as resolved.
        skipped_now = bool(was) and was.get("category") in now.skipped

        if is_open and not was_open:
            diff.regressions.append(
                FindingChange(
                    finding_id=finding_id,
                    title=is_now["title"],
                    severity=is_now["severity"],
                    previous_status=was["status"] if was else None,
                    current_status=is_now["status"],
                    evidence=is_now.get("evidence", ""),
                    recommendation=is_now.get("recommendation", ""),
                )
            )
        elif was_open and (_is_closed(is_now["status"]) if is_now else not skipped_now):
            # Only a finding the scanner actually re-checked, and found clear, counts as fixed.
            # FAIL -> UNKNOWN means it could not see it, which is not good news.
            diff.improvements.append(
                FindingChange(
                    finding_id=finding_id,
                    title=was["title"],
                    severity=was["severity"],
                    previous_status=was["status"],
                    current_status=is_now["status"] if is_now else None,
                )
            )

    for key in sorted(set(now.vulnerabilities) - set(before.vulnerabilities)):
        diff.new_vulnerabilities.append(now.vulnerabilities[key])
    for key in sorted(set(before.vulnerabilities) - set(now.vulnerabilities)):
        diff.resolved_vulnerabilities.append(before.vulnerabilities[key])

    return diff


def summarise(diffs: list[ScanDiff]) -> dict[str, Any]:
    """One line's worth of numbers for a notification headline."""
    changed = [d for d in diffs if d.has_changes and not d.first_scan]
    return {
        "sites_scanned": len(diffs),
        "sites_changed": len(changed),
        "new_findings": sum(len(d.regressions) for d in changed),
        "resolved_findings": sum(len(d.improvements) for d in changed),
        "new_vulnerabilities": sum(len(d.new_vulnerabilities) for d in changed),
        "resolved_vulnerabilities": sum(len(d.resolved_vulnerabilities) for d in changed),
        "unreachable": sum(1 for d in diffs if d.became_unreachable),
    }


def finding_from_change(change: FindingChange) -> Finding:
    """Rebuild a Finding from a change, for renderers that take findings."""
    return Finding(
        id=change.finding_id,
        category="Change",
        title=change.title,
        severity=Severity(change.severity),
        status=Status(change.current_status or Status.UNKNOWN.value),
        evidence=change.evidence,
        recommendation=change.recommendation,
    )
