"""Shared result types.

Every check produces `Finding` objects with the same shape so the report can be sorted, scored and
handed to a customer without each check inventing its own vocabulary.

`Severity` says how bad the issue is. `Status` says what the check actually observed. The two are
independent: a high-severity check that passed contributes nothing to the score, and an
`UNKNOWN` status exists because a scan from the outside genuinely cannot see everything -- a check
that could not run says so instead of reporting a pass that was never verified.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        """Sort order, worst first."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Map a CVSS base score onto the severity vocabulary used here.

        The cut-offs are the CVSS v3.1 qualitative ratings. A vulnerability with no score is
        treated as HIGH rather than guessed downwards: an advisory that exists at all is worth
        looking at, and under-reporting a real vulnerability is the more expensive mistake.
        """
        if score is None:
            return cls.HIGH
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Status(enum.Enum):
    FAIL = "Fail"
    WARN = "Warn"
    UNKNOWN = "Unknown"
    INFO = "Info"
    PASS = "Pass"

    @property
    def rank(self) -> int:
        """Sort order: what needs doing first comes first."""
        return _STATUS_RANK[self]


_STATUS_RANK = {
    Status.FAIL: 0,
    Status.WARN: 1,
    Status.UNKNOWN: 2,
    Status.INFO: 3,
    Status.PASS: 4,
}


@dataclass
class Finding:
    """One observation about the site.

    `id` is stable across scans so two reports can be diffed; `evidence` is what the scanner
    actually saw, so any finding can be traced back to the request that produced it.
    """

    id: str
    category: str
    title: str
    severity: Severity
    status: Status
    evidence: str = ""
    recommendation: str = ""
    reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data


@dataclass
class Component:
    """A plugin or theme the site was seen loading."""

    kind: str  # "plugin" or "theme"
    slug: str
    version: str | None = None
    latest_version: str | None = None
    status: str = "Unknown"  # Current | Outdated | NotInDirectory | Unknown
    evidence: str = ""
    vulnerabilities: list[VulnerabilityMatch] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "slug": self.slug,
            "version": self.version,
            "latest_version": self.latest_version,
            "status": self.status,
            "evidence": self.evidence,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


@dataclass
class VulnerabilityMatch:
    """A published vulnerability whose affected range covers the version that was detected.

    This is a version match, not an exploit check. Nothing is sent to the site to confirm it, so a
    match means "the version this site reports is in the affected range" -- which is what a
    defender should act on, while remembering that a backported distribution patch or a wrong
    version string can make it wrong in either direction.
    """

    source: str
    vuln_id: str
    title: str
    cve: str | None = None
    cvss_score: float | None = None
    cvss_rating: str | None = None
    patched_in: str | None = None
    published: str | None = None
    references: list[str] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return Severity.from_cvss(self.cvss_score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "vuln_id": self.vuln_id,
            "title": self.title,
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "cvss_rating": self.cvss_rating,
            "patched_in": self.patched_in,
            "published": self.published,
            "references": self.references,
            "severity": self.severity.value,
        }


@dataclass
class ScanReport:
    url: str
    final_url: str | None = None
    scanned_at: str = ""
    completed: bool = False
    is_wordpress: bool = False
    wordpress_version: str | None = None
    latest_wordpress_version: str | None = None
    score: int = 0
    grade: str = "F"
    summary: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    certificate: dict[str, Any] | None = None
    vulnerability_db: dict[str, Any] | None = None
    requests_made: int = 0
    #: Check groups this scan did not run, so a later diff does not read their absence as a fix.
    skipped: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "scanned_at": self.scanned_at,
            "completed": self.completed,
            "is_wordpress": self.is_wordpress,
            "wordpress_version": self.wordpress_version,
            "latest_wordpress_version": self.latest_wordpress_version,
            "score": self.score,
            "grade": self.grade,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "components": [c.to_dict() for c in self.components],
            "certificate": self.certificate,
            "vulnerability_db": self.vulnerability_db,
            "requests_made": self.requests_made,
            "skipped": self.skipped,
            "error": self.error,
        }
