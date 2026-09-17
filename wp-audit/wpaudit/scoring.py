"""Turning findings into a score and a grade.

The score exists so a scan can be put in front of a customer and compared to last month's. It is a
weighted deduction, not a measurement: a site with no findings scores 100, and each failed check
subtracts by severity. A warning subtracts half, because a warning is something that is configured
but weakly.

Deductions are capped per severity band so the grade keeps tracking the *worst* problem rather than
the *number* of problems. Without the cap, a site with a dozen missing headers and nothing else
grades below a site that is serving its database credentials, which would be a report that actively
misleads the person reading it.

An `UNKNOWN` status subtracts nothing. The scan could not see it, and a guess in either direction
would be worse than saying so.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Severity, Status

WEIGHTS = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 18.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}

#: Most a single severity band can take off in total.
CAPS = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 54.0,
    Severity.MEDIUM: 32.0,
    Severity.LOW: 15.0,
    Severity.INFO: 0.0,
}

GRADE_BOUNDARIES = ((90, "A"), (80, "B"), (70, "C"), (50, "D"))


@dataclass
class RiskScore:
    score: int
    grade: str
    summary: dict[str, int]


def score_findings(findings: list[Finding]) -> RiskScore:
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "passed": 0,
        "unknown": 0,
    }
    deductions = {severity: 0.0 for severity in WEIGHTS}

    for finding in findings:
        if finding.status is Status.PASS:
            summary["passed"] += 1
            continue
        if finding.status is Status.UNKNOWN:
            summary["unknown"] += 1
            continue
        if finding.status is Status.INFO:
            summary["informational"] += 1
            continue
        if finding.status not in (Status.FAIL, Status.WARN):
            continue

        if finding.severity is Severity.INFO:
            summary["informational"] += 1
        else:
            summary[finding.severity.value.lower()] += 1

        deduction = WEIGHTS[finding.severity]
        if finding.status is Status.WARN:
            deduction /= 2
        deductions[finding.severity] += deduction

    total = sum(min(deductions[severity], CAPS[severity]) for severity in WEIGHTS)
    score = round(max(0.0, 100.0 - total))

    grade = "F"
    for boundary, letter in GRADE_BOUNDARIES:
        if score >= boundary:
            grade = letter
            break

    return RiskScore(score=score, grade=grade, summary=summary)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """What needs doing first, first: failures before warnings, worst severity before least."""
    return sorted(findings, key=lambda f: (f.status.rank, f.severity.rank, f.id))
