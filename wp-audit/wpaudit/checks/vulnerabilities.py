"""Matching what the site runs against published vulnerabilities.

This is the part that answers "which known holes does this site have", and it is worth being
precise about what it can and cannot claim.

What it does: takes the version the site reports for core and for each detected component, and
looks up advisories whose affected range covers that version. That is exactly what an attacker
does, from the same public data, which is why it is worth doing first.

What it does not do: confirm exploitability. Nothing is sent to the site to test a finding, so
every match is a *version* match. Two things follow, and both are stated in the findings rather
than hidden:

  * False positives. A host that backports security fixes without changing the version string, or
    a site whose version string is simply wrong, will match advisories it is not vulnerable to.
  * False negatives. A component whose version could not be read is not matched at all, and a
    vulnerability with no advisory published yet cannot be matched by anyone.

A component with no matches is therefore reported as "nothing published for this version", never
as "safe".
"""

from __future__ import annotations

from ..models import Component, Finding, Severity, Status
from ..vulndb.store import VulnerabilityDatabase

CORE_SLUG = "wordpress"


def check_vulnerabilities(
    database: VulnerabilityDatabase,
    *,
    core_version: str | None,
    components: list[Component],
) -> list[Finding]:
    findings: list[Finding] = []
    info = database.info()

    if not info.exists or info.record_count == 0:
        return [
            Finding(
                id="VULN-DB-MISSING",
                category="Vulnerabilities",
                title="No vulnerability database is available",
                severity=Severity.HIGH,
                status=Status.UNKNOWN,
                evidence=f"No data at {info.path}.",
                recommendation=(
                    "Run 'wp-audit update' to download the vulnerability feed. Until then this "
                    "scan reports configuration and version currency only, and says nothing about "
                    "known vulnerabilities."
                ),
            )
        ]

    if info.age_hours is not None and info.age_hours > 168:
        findings.append(
            Finding(
                id="VULN-DB-STALE",
                category="Vulnerabilities",
                title="The vulnerability database is out of date",
                severity=Severity.MEDIUM,
                status=Status.WARN,
                evidence=(
                    f"Last updated {info.updated_at} ({info.age_hours / 24:.0f} days ago), "
                    f"{info.record_count:,} records."
                ),
                recommendation=(
                    "Run 'wp-audit update' - ideally from a daily scheduled task. Vulnerabilities "
                    "published since that date cannot be matched, so a clean result here is only "
                    "as current as the feed."
                ),
            )
        )

    findings.extend(_check_core(database, core_version))

    unmatched: list[str] = []
    for component in components:
        if not component.version:
            unmatched.append(f"{component.slug} ({component.kind})")
            continue
        component.vulnerabilities = database.match(component.kind, component.slug, component.version)
        findings.extend(_component_findings(component))

    if unmatched:
        findings.append(
            Finding(
                id="VULN-VERSION-UNKNOWN",
                category="Vulnerabilities",
                title="Some components could not be version-matched",
                severity=Severity.MEDIUM,
                status=Status.UNKNOWN,
                evidence="No version was readable for: " + ", ".join(sorted(unmatched)[:10]),
                recommendation=(
                    "These were detected but carry no version, usually because an asset optimiser "
                    "strips the ?ver= query string. Re-run with --confirm-components to read each "
                    "component's readme.txt, or check them from the admin dashboard - they are "
                    "invisible to vulnerability matching until then."
                ),
            )
        )

    total = sum(len(c.vulnerabilities) for c in components)
    if not total and not any(f.id.startswith("VULN-CORE") and f.status is Status.FAIL for f in findings):
        findings.append(
            Finding(
                id="VULN-NONE-MATCHED",
                category="Vulnerabilities",
                title="No published vulnerabilities match the detected versions",
                severity=Severity.HIGH,
                status=Status.PASS,
                evidence=(
                    f"Checked against {info.record_count:,} advisories covering "
                    f"{info.component_count:,} components, last updated {info.updated_at}."
                ),
                recommendation=(
                    "This means nothing is published for these versions today. It is not a "
                    "guarantee: undisclosed vulnerabilities exist, and a component whose version "
                    "could not be read was not matched."
                ),
            )
        )

    return findings


def _check_core(database: VulnerabilityDatabase, core_version: str | None) -> list[Finding]:
    if not core_version:
        return []

    matches = database.match("core", CORE_SLUG, core_version)
    if not matches:
        return [
            Finding(
                id="VULN-CORE-NONE",
                category="Vulnerabilities",
                title=f"No published vulnerabilities match WordPress {core_version}",
                severity=Severity.HIGH,
                status=Status.PASS,
                evidence=f"WordPress core {core_version} matched no advisories in the database.",
            )
        ]

    # The worst match sets the severity of the finding: a critical among five mediums is what the
    # reader has to act on today.
    severity = min((m.severity for m in matches), key=lambda s: s.rank)
    patched = sorted({m.patched_in for m in matches if m.patched_in})

    return [
        Finding(
            id="VULN-CORE",
            category="Vulnerabilities",
            title=f"WordPress {core_version} has {len(matches)} published vulnerability(ies)",
            severity=severity,
            status=Status.FAIL,
            evidence=_format_matches(matches),
            recommendation=(
                "Update WordPress core"
                + (f" to at least {patched[-1]}" if patched else "")
                + ". These are published advisories against the exact version this site reports."
            ),
            reference=matches[0].references[0] if matches[0].references else "",
        )
    ]


def _component_findings(component: Component) -> list[Finding]:
    if not component.vulnerabilities:
        return []

    matches = component.vulnerabilities
    severity = min((m.severity for m in matches), key=lambda s: s.rank)
    patched = sorted({m.patched_in for m in matches if m.patched_in})
    fix = f" Update to at least {patched[-1]}." if patched else (
        " No fixed version is published yet - consider disabling it until one is."
    )

    return [
        Finding(
            id=f"VULN-{component.kind.upper()}-{component.slug.upper()}",
            category="Vulnerabilities",
            title=(
                f"{component.kind.title()} '{component.slug}' {component.version} has "
                f"{len(matches)} published vulnerability(ies)"
            ),
            severity=severity,
            status=Status.FAIL,
            evidence=_format_matches(matches),
            recommendation=(
                f"Detected version {component.version} falls inside the affected range of the "
                f"advisories above.{fix}"
            ),
            reference=matches[0].references[0] if matches[0].references else "",
        )
    ]


def _format_matches(matches, limit: int = 5) -> str:
    lines = []
    for match in matches[:limit]:
        parts = [match.title or match.vuln_id]
        if match.cve:
            parts.append(match.cve)
        if match.cvss_score is not None:
            parts.append(f"CVSS {match.cvss_score}")
        if match.patched_in:
            parts.append(f"fixed in {match.patched_in}")
        lines.append(" | ".join(parts))
    if len(matches) > limit:
        lines.append(f"...and {len(matches) - limit} more")
    return "; ".join(lines)
