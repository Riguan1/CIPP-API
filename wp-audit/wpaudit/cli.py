"""Command line interface.

Two verbs, because they fail for different reasons and belong on different schedules:

    wp-audit update              refresh the local vulnerability database (nightly cron)
    wp-audit scan <site...>      scan one site, or a file of them (whenever you like)

Exit codes are meant for that cron job: 0 clean, 1 findings at or above the threshold, 2 a scan
could not be completed, 3 the tool itself failed. So `wp-audit scan --fail-on high -q sites.txt`
in a scheduled task is silent until something needs attention.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks.components import WordPressOrg
from .models import ScanReport, Severity, Status
from .report import render_html, render_json, render_text
from .scanner import scan
from .vulndb.sources import WordfenceSource, WPScanSource, load_feed_file
from .vulndb.store import VulnerabilityDatabase, default_db_path, iter_progress

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_SCAN_FAILED = 2
EXIT_ERROR = 3

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

AUTHORISATION_NOTE = (
    "Scan only sites you own or are engaged to assess. Unauthorised scanning is an offence in most "
    "jurisdictions, however gentle the requests."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp-audit",
        description="Passive security scanner for WordPress websites. " + AUTHORISATION_NOTE,
    )
    parser.add_argument("--version", action="version", version=f"wp-audit {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    update = subparsers.add_parser(
        "update",
        help="download the vulnerability feed into the local database",
        description=(
            "Downloads the Wordfence Intelligence vulnerability feed (free, no API key, CC BY-SA "
            "4.0) and indexes it locally. Run this from a nightly scheduled task so scans keep "
            "matching against current data."
        ),
    )
    update.add_argument("--db", default=None, help=f"database path (default: {default_db_path()})")
    update.add_argument("--feed-url", default=None, help="override the feed URL")
    update.add_argument(
        "--from-file", default=None, help="index a feed already downloaded, for offline use"
    )
    update.add_argument("--timeout", type=float, default=120.0, help="download timeout in seconds")
    update.add_argument("--quiet", "-q", action="store_true")

    scan_parser = subparsers.add_parser(
        "scan",
        help="scan one or more sites",
        description="Runs a passive, read-only assessment. " + AUTHORISATION_NOTE,
    )
    scan_parser.add_argument("targets", nargs="*", help="site URLs or bare hostnames")
    scan_parser.add_argument(
        "-f", "--file", default=None, help="file with one site per line (# comments allowed)"
    )
    scan_parser.add_argument("--db", default=None, help="vulnerability database path")
    scan_parser.add_argument(
        "--no-vulndb", action="store_true", help="skip vulnerability matching entirely"
    )
    scan_parser.add_argument(
        "--wpscan-token",
        default=None,
        help="also query the WPScan API for detected components (uses its daily quota)",
    )
    scan_parser.add_argument("--timeout", type=float, default=15.0, help="per-request timeout")
    scan_parser.add_argument(
        "--max-requests", type=int, default=30, help="request ceiling per site (default 30)"
    )
    scan_parser.add_argument(
        "--confirm-components",
        action="store_true",
        help="read each component's readme.txt to pin its version (one extra request each)",
    )
    scan_parser.add_argument(
        "--skip-exposure", action="store_true", help="home page checks only (two requests)"
    )
    scan_parser.add_argument(
        "--skip-version-lookup", action="store_true", help="do not contact WordPress.org"
    )
    scan_parser.add_argument(
        "--format", choices=["text", "json", "html"], default="text", help="output format"
    )
    scan_parser.add_argument("-o", "--output", default=None, help="write the report to a file")
    scan_parser.add_argument(
        "--show-passed", action="store_true", help="include checks that passed in text output"
    )
    scan_parser.add_argument("--no-colour", action="store_true", help="disable ANSI colour")
    scan_parser.add_argument(
        "--fail-on",
        choices=[*SEVERITY_ORDER, "never"],
        default="never",
        help="exit 1 when a finding at or above this severity is present",
    )
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="only write the report file")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "update":
            return _run_update(args)
        return _run_scan(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR


def _run_update(args) -> int:
    database = VulnerabilityDatabase(args.db)
    source = WordfenceSource(args.feed_url or WordfenceSource().url, timeout=args.timeout)

    if not args.quiet:
        origin = args.from_file or source.url
        print(f"Updating {database.path}\n  from {origin}")

    try:
        payload = load_feed_file(args.from_file) if args.from_file else source.fetch()
    except Exception as exc:  # network, JSON, or filesystem - all the same to the caller
        print(f"Could not retrieve the vulnerability feed: {exc}", file=sys.stderr)
        print(
            "  The previous database (if any) is untouched. If this network cannot reach "
            "wordfence.com, download the feed elsewhere and use --from-file.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    records = source.parse(payload)
    if not args.quiet:
        records = iter_progress(records)

    count = database.replace_source(source.name, records, attribution=source.attribution)
    info = database.info()

    if not args.quiet:
        print(
            f"Indexed {count:,} advisory records covering {info.component_count:,} components."
        )
        print(f"  {source.attribution}")
    return EXIT_OK


def _read_targets(args) -> list[str]:
    targets = list(args.targets)
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(line)
    # Keep the caller's order but drop repeats: a site list assembled from several sources
    # routinely names the same customer twice.
    return list(dict.fromkeys(targets))


def _run_scan(args) -> int:
    targets = _read_targets(args)
    if not targets:
        print("No targets given. Pass URLs, or -f with a file of them.", file=sys.stderr)
        return EXIT_ERROR

    database = None
    if not args.no_vulndb:
        database = VulnerabilityDatabase(args.db)
        info = database.info()
        if not info.exists or info.record_count == 0:
            print(
                "No vulnerability database found - run 'wp-audit update' first. "
                "Scanning without it: configuration and version checks only.",
                file=sys.stderr,
            )
        elif info.age_hours and info.age_hours > 168:
            print(
                f"Vulnerability database is {info.age_hours / 24:.0f} days old; "
                "run 'wp-audit update' for current data.",
                file=sys.stderr,
            )

    client = WordPressOrg(enabled=not args.skip_version_lookup)
    reports: list[ScanReport] = []

    for target in targets:
        report = scan(
            target,
            timeout=args.timeout,
            max_requests=args.max_requests,
            skip_version_lookup=args.skip_version_lookup,
            skip_exposure=args.skip_exposure,
            confirm_components=args.confirm_components,
            database=database,
            wordpress_org=client,
        )
        if args.wpscan_token and report.completed:
            _enrich_with_wpscan(report, args.wpscan_token)
        reports.append(report)

        if args.format == "text" and not args.quiet:
            print(render_text(report, colour=not args.no_colour, show_passed=args.show_passed), end="")

    output = _render(args, reports)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"\nWrote {args.output}")
    elif args.format != "text":
        print(output)

    if database is not None:
        database.close()

    return _exit_code(reports, args.fail_on)


def _render(args, reports: list[ScanReport]) -> str:
    if args.format == "json":
        return render_json(reports)
    if args.format == "html":
        return render_html(reports)
    return "".join(
        render_text(report, colour=False, show_passed=args.show_passed) for report in reports
    )


def _enrich_with_wpscan(report: ScanReport, token: str) -> None:
    """Add WPScan's view of each detected component, on top of whatever the local database found.

    Kept strictly opt-in: the free tier allows 25 requests a day and every component costs one, so
    an unattended sweep would burn the quota on the first site.
    """
    try:
        source = WPScanSource(token)
    except ValueError:
        return

    for component in report.components:
        if not component.version:
            continue
        try:
            records = source.lookup(component.kind, component.slug, component.version)
        except Exception as exc:
            report.findings.append(
                _wpscan_error_finding(str(exc))
            )
            return

        from .models import VulnerabilityMatch
        from .versions import version_in_range

        known = {(m.source, m.vuln_id) for m in component.vulnerabilities}
        for record in records:
            if (record.source, record.vuln_id) in known:
                continue
            if not version_in_range(
                component.version,
                record.from_version,
                record.from_inclusive,
                record.to_version,
                record.to_inclusive,
            ):
                continue
            component.vulnerabilities.append(
                VulnerabilityMatch(
                    source=record.source,
                    vuln_id=record.vuln_id,
                    title=record.title,
                    cve=record.cve,
                    cvss_score=record.cvss_score,
                    patched_in=record.patched_in,
                    published=record.published,
                    references=record.references,
                )
            )


def _wpscan_error_finding(message: str):
    from .models import Finding

    return Finding(
        id="VULN-WPSCAN-ERROR",
        category="Vulnerabilities",
        title="The WPScan lookup did not complete",
        severity=Severity.MEDIUM,
        status=Status.UNKNOWN,
        evidence=message,
        recommendation=(
            "Results from the local database are still shown. The WPScan free tier allows 25 "
            "requests a day, which one site with many plugins can exhaust."
        ),
    )


def _exit_code(reports: list[ScanReport], fail_on: str) -> int:
    if any(not report.completed for report in reports):
        return EXIT_SCAN_FAILED
    if fail_on == "never":
        return EXIT_OK

    threshold = SEVERITY_ORDER.index(fail_on)
    for report in reports:
        for finding in report.findings:
            if finding.status not in (Status.FAIL, Status.WARN):
                continue
            if SEVERITY_ORDER.index(finding.severity.value.lower()) <= threshold:
                return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
