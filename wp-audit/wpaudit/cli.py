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
from .alerts import match_inventory, new_matches, render_feed_alert
from .checks.components import WordPressOrg
from .diff import ScanDiff, compare
from .history import ScanHistory, default_history_path, site_key
from .models import ScanReport, Severity, Status
from .notify import WEBHOOK_FORMATS, build_payload, render_summary_text, send_webhook
from .report import render_html, render_json, render_text
from .scanner import scan
from .vulndb.sources import (
    WORDFENCE_TOKEN_ENV,
    FeedAuthError,
    WordfenceSource,
    WPScanSource,
    load_feed_file,
)
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
            "Downloads the Wordfence Intelligence vulnerability feed (free, CC BY-SA 4.0) and "
            "indexes it locally. Run this from a nightly scheduled task so scans keep matching "
            f"against current data. v3 of the feed needs an API token: set {WORDFENCE_TOKEN_ENV} "
            "or pass --wordfence-token."
        ),
    )
    update.add_argument("--db", default=None, help=f"database path (default: {default_db_path()})")
    update.add_argument(
        "--wordfence-token",
        default=None,
        help=(
            f"Wordfence API token (free, from Integrations in your account dashboard). Prefer the "
            f"{WORDFENCE_TOKEN_ENV} environment variable - a token on the command line is visible "
            "in the process list."
        ),
    )
    update.add_argument(
        "--feed",
        choices=["scanner", "production"],
        default="scanner",
        help="scanner (default, includes vulnerabilities still being researched) or production",
    )
    update.add_argument(
        "--feed-version",
        choices=["v3", "v2"],
        default="v3",
        help="feed API version. v2 needs no token but is being retired",
    )
    update.add_argument("--feed-url", default=None, help="override the feed URL entirely")
    update.add_argument(
        "--from-file", default=None, help="index a feed already downloaded, for offline use"
    )
    update.add_argument("--timeout", type=float, default=120.0, help="download timeout in seconds")
    update.add_argument(
        "--alert-known",
        action="store_true",
        help=(
            "after updating, report advisories that now match components already seen on scanned "
            "sites - the answer to 'does today's feed affect any of my customers'"
        ),
    )
    update.add_argument("--history", default=None, help="scan history path (for --alert-known)")
    update.add_argument("--webhook", default=None, help="post the alert to this URL")
    update.add_argument(
        "--webhook-format", choices=list(WEBHOOK_FORMATS), default="json", help="webhook payload shape"
    )
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
    scan_parser.add_argument(
        "--history", default=None, help=f"scan history path (default: {default_history_path()})"
    )
    scan_parser.add_argument(
        "--no-history", action="store_true", help="do not record this scan or compare with the last"
    )
    scan_parser.add_argument(
        "--only-changes",
        action="store_true",
        help=(
            "print only what changed since the previous scan, and nothing at all when nothing did "
            "- so a cron job mails you only when something happened"
        ),
    )
    scan_parser.add_argument(
        "--fail-on-change",
        action="store_true",
        help="exit 1 when anything got worse since the previous scan",
    )
    scan_parser.add_argument("--webhook", default=None, help="post a change summary to this URL")
    scan_parser.add_argument(
        "--webhook-format", choices=list(WEBHOOK_FORMATS), default="json", help="webhook payload shape"
    )
    scan_parser.add_argument(
        "--prune", type=int, default=50, help="scans to keep per site in the history (default 50)"
    )

    history_parser = subparsers.add_parser(
        "history",
        help="show what has been scanned and how it has trended",
        description="Reads the local scan history. Makes no network requests.",
    )
    history_parser.add_argument("site", nargs="?", help="a site to show the trend for")
    history_parser.add_argument("--history", default=None, help="scan history path")
    history_parser.add_argument("--limit", type=int, default=10, help="scans to show")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "update":
            return _run_update(args)
        if args.command == "history":
            return _run_history(args)
        return _run_scan(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR


def _run_update(args) -> int:
    database = VulnerabilityDatabase(args.db)
    source = WordfenceSource(
        args.feed_url,
        version=args.feed_version,
        variant=args.feed,
        token=args.wordfence_token,
        timeout=args.timeout,
    )

    if not args.quiet:
        origin = args.from_file or source.url
        print(f"Updating {database.path}\n  from {origin}")

    try:
        payload = load_feed_file(args.from_file) if args.from_file else source.fetch()
    except FeedAuthError as exc:
        # Worth its own message: a token problem and a network problem look identical from the
        # outside and need completely different fixes.
        print(f"{exc}", file=sys.stderr)
        print("  The previous database (if any) is untouched.", file=sys.stderr)
        return EXIT_ERROR
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

    # What already matched, before the new data lands. Anything matching afterwards that is not in
    # this set is genuinely new to these sites, rather than something they have had all along.
    history = None
    before: list = []
    if args.alert_known:
        history = ScanHistory(args.history)
        before = match_inventory(database, history)

    count = database.replace_source(source.name, records, attribution=source.attribution)
    info = database.info()

    if not args.quiet:
        print(f"Indexed {count:,} advisory records covering {info.component_count:,} components.")
        print(f"  {source.attribution}")

    exit_code = EXIT_OK
    if args.alert_known and history is not None:
        fresh = new_matches(before, match_inventory(database, history))
        text = render_feed_alert(fresh)
        if text:
            print()
            print(text)
            exit_code = EXIT_FINDINGS
            if args.webhook:
                payload = build_payload([], feed_alert_text=text, feed_alert_count=len(fresh))
                delivered, error = send_webhook(args.webhook, payload, args.webhook_format)
                if not delivered:
                    print(f"Webhook delivery failed: {error}", file=sys.stderr)
        elif not args.quiet:
            print("\nNothing in this update affects a component seen on a scanned site.")
        history.close()

    return exit_code


def _run_history(args) -> int:
    history = ScanHistory(args.history)
    try:
        if not args.site:
            sites = history.sites()
            if not sites:
                print("No scans recorded yet.")
                return EXIT_OK
            print(f"{len(sites)} site(s) in {history.path}, {history.count()} scan(s) recorded:\n")
            for site in sites:
                trend = history.trend(site, limit=1)
                last = trend[0] if trend else {}
                state = (
                    f"{last.get('score')}/100 grade {last.get('grade')}"
                    if last.get("completed")
                    else "could not be scanned"
                )
                print(f"  {site:<40} {state}  ({last.get('scanned_at', '')})")
            return EXIT_OK

        key = site_key(args.site)
        trend = history.trend(key, limit=args.limit)
        if not trend:
            print(f"No scans recorded for {key}.")
            return EXIT_OK

        print(f"{key} - most recent first\n")
        for entry in trend:
            if entry["completed"]:
                print(f"  {entry['scanned_at']}  {entry['score']:>3}/100  {entry['grade']}  "
                      f"WordPress {entry['wordpress_version'] or '?'}")
            else:
                print(f"  {entry['scanned_at']}    -      -  could not be scanned")
        return EXIT_OK
    finally:
        history.close()


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

    history = None if args.no_history else ScanHistory(args.history)
    client = WordPressOrg(enabled=not args.skip_version_lookup)
    reports: list[ScanReport] = []
    diffs: list[ScanDiff] = []

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

        if history is not None:
            # Read the previous scan before recording this one, or the diff compares the scan
            # against itself.
            key = site_key(report)
            previous = history.previous(key)
            diffs.append(compare(previous, report, site=key))
            history.record(report)
        else:
            diffs.append(compare(None, report, site=site_key(report)))

        # --only-changes owns stdout: printing the full report as well would defeat the point of
        # a job that is supposed to be silent when nothing happened.
        if args.format == "text" and not args.quiet and not args.only_changes:
            print(render_text(report, colour=not args.no_colour, show_passed=args.show_passed), end="")

    if history is not None:
        if args.prune > 0:
            history.prune(args.prune)
        history.close()

    if args.only_changes and not args.quiet:
        _print_changes(diffs, colour=not args.no_colour)

    output = _render(args, reports, diffs)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"\nWrote {args.output}")
    elif args.format != "text":
        print(output)

    if args.webhook:
        _post_changes(args, diffs)

    if database is not None:
        database.close()

    if args.fail_on_change and any(_got_worse(diff) for diff in diffs):
        return EXIT_FINDINGS
    return _exit_code(reports, args.fail_on)


def _got_worse(diff: ScanDiff) -> bool:
    return bool(diff.regressions or diff.new_vulnerabilities or diff.became_unreachable)


def _print_changes(diffs: list[ScanDiff], *, colour: bool) -> None:
    """Print the delta, and print nothing at all when there is none.

    The silence is the feature: cron mails whatever a job prints, so a quiet night sends no mail.
    """
    text = render_summary_text(diffs)
    first = [d for d in diffs if d.first_scan and d.completed]
    if not text and not first:
        return

    if text:
        print(text)
    for diff in first:
        print(f"{diff.site}: first scan, {diff.current_score}/100 grade {diff.current_grade} "
              "(nothing to compare against yet)")


def _post_changes(args, diffs: list[ScanDiff]) -> None:
    if not any(diff.has_changes and not diff.first_scan for diff in diffs):
        return
    payload = build_payload(diffs)
    delivered, error = send_webhook(args.webhook, payload, args.webhook_format)
    if not delivered:
        # The findings are on stdout and in the history either way; a failed post must not look
        # like a clean run.
        print(f"Webhook delivery failed: {error}", file=sys.stderr)


def _render(args, reports: list[ScanReport], diffs: list[ScanDiff] | None = None) -> str:
    if args.format == "json":
        return render_json(reports, diffs)
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
