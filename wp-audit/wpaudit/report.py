"""Rendering a scan: terminal, JSON, and a single-file HTML report to send to a customer."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .models import ScanReport, Severity, Status

RESET = "\033[0m"
BOLD = "\033[1m"
COLOURS = {
    Severity.CRITICAL: "\033[95m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}
STATUS_MARK = {
    Status.FAIL: "x",
    Status.WARN: "!",
    Status.UNKNOWN: "?",
    Status.INFO: "i",
    Status.PASS: "+",
}


def render_text(report: ScanReport, *, colour: bool = True, show_passed: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if colour else text

    lines: list[str] = []
    title = report.final_url or report.url
    lines.append(paint(f"\n{title}", BOLD))

    if not report.completed:
        lines.append(f"  could not be scanned: {report.error}")
        return "\n".join(lines) + "\n"

    grade_colour = {
        "A": "\033[92m", "B": "\033[92m", "C": "\033[93m", "D": "\033[91m", "F": "\033[95m"
    }.get(report.grade, "")
    lines.append(
        f"  score {paint(str(report.score) + '/100', BOLD)}  "
        f"grade {paint(report.grade, grade_colour)}  "
        f"({report.requests_made} requests)"
    )

    if report.is_wordpress:
        version = report.wordpress_version or "unknown version"
        latest = f" (current: {report.latest_wordpress_version})" if report.latest_wordpress_version else ""
        lines.append(f"  WordPress {version}{latest}, {len(report.components)} component(s) detected")
    else:
        lines.append("  WordPress was not detected on this page")

    if report.vulnerability_db:
        info = report.vulnerability_db
        age = info.get("age_hours")
        age_text = f", {age / 24:.0f} days old" if age else ""
        lines.append(
            f"  vulnerability data: {info.get('record_count', 0):,} advisories"
            f"{age_text} ({', '.join(info.get('sources') or []) or 'none'})"
        )

    summary = report.summary or {}
    lines.append(
        "  "
        + "  ".join(
            f"{label}: {summary.get(key, 0)}"
            for key, label in (
                ("critical", "critical"),
                ("high", "high"),
                ("medium", "medium"),
                ("low", "low"),
                ("unknown", "unchecked"),
                ("passed", "passed"),
            )
        )
    )
    lines.append("")

    for finding in report.findings:
        if finding.status is Status.PASS and not show_passed:
            continue
        mark = STATUS_MARK[finding.status]
        severity = paint(f"{finding.severity.value:<8}", COLOURS[finding.severity])
        lines.append(f"  [{mark}] {severity} {finding.title}")
        if finding.evidence:
            lines.append(f"        {finding.evidence}")
        if finding.recommendation and finding.status in (Status.FAIL, Status.WARN, Status.UNKNOWN):
            lines.append(f"        -> {finding.recommendation}")

    return "\n".join(lines) + "\n"


def render_json(reports: list[ScanReport], diffs=None) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scans": [report.to_dict() for report in reports],
    }
    if diffs is not None:
        # Whatever consumes the JSON gets the same delta the terminal and the webhook get, rather
        # than having to store the previous run and work it out again.
        payload["changes"] = [diff.to_dict() for diff in diffs]
    return json.dumps(payload, indent=2)


def render_html(reports: list[ScanReport]) -> str:
    """A self-contained report page.

    No external stylesheet, font or script: the file has to survive being emailed to a customer and
    opened from a download folder, and a report that phones out to a CDN is also a report that
    tells someone else which sites you audited.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = "\n".join(_html_card(report) for report in reports)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WordPress security report</title>
<style>
  :root {{
    --bg: #ffffff; --fg: #1a1a1a; --muted: #5c5c5c; --line: #e3e3e3; --card: #fafafa;
    --critical: #7c2d92; --high: #c62828; --medium: #e08600; --low: #0277bd; --pass: #2e7d32;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #16181c; --fg: #e8e8e8; --muted: #a0a0a0; --line: #2c3038; --card: #1d2026;
      --critical: #d18ae8; --high: #ef6b6b; --medium: #f0b44a; --low: #6cc4f5; --pass: #7bc67b;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 24px 16px; background: var(--bg); color: var(--fg);
         font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  .wrap {{ max-width: 920px; margin: 0 auto; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-bottom: 28px; }}
  .site {{ border: 1px solid var(--line); border-radius: 10px; padding: 18px; margin-bottom: 20px;
           background: var(--card); }}
  .site h2 {{ font-size: 17px; margin: 0 0 10px; word-break: break-all; }}
  .grade {{ display: inline-block; min-width: 34px; text-align: center; padding: 2px 8px;
            border-radius: 6px; font-weight: 700; color: #fff; }}
  .counts {{ color: var(--muted); font-size: 13px; margin: 8px 0 16px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 8px 6px; border-top: 1px solid var(--line); vertical-align: top; }}
  td.sev {{ width: 86px; font-weight: 600; font-size: 13px; white-space: nowrap; }}
  .evidence, .rec {{ color: var(--muted); font-size: 13px; margin-top: 3px; word-break: break-word; }}
  .rec::before {{ content: "→ "; }}
  .Critical {{ color: var(--critical); }} .High {{ color: var(--high); }}
  .Medium {{ color: var(--medium); }} .Low {{ color: var(--low); }}
  .Info {{ color: var(--muted); }} .Pass {{ color: var(--pass); }}
  footer {{ color: var(--muted); font-size: 12px; margin-top: 32px; border-top: 1px solid var(--line);
            padding-top: 14px; }}
</style></head>
<body><div class="wrap">
<h1>WordPress security report</h1>
<div class="meta">Generated {generated} by wp-audit &middot; passive, read-only assessment</div>
{cards}
<footer>
  Every check in this report is read-only: it reads what each site publishes to anonymous visitors.
  It finds misconfiguration, missing updates and published vulnerabilities affecting the versions
  detected. It does not confirm exploitability, and it cannot see undisclosed vulnerabilities or
  anything behind a login, so a clean result is evidence of good hygiene rather than proof that a
  site cannot be compromised.
</footer>
</div></body></html>
"""


def _html_card(report: ScanReport) -> str:
    site = html.escape(report.final_url or report.url)
    if not report.completed:
        return (
            f'<div class="site"><h2>{site}</h2>'
            f'<div class="counts">Could not be scanned: {html.escape(report.error)}</div></div>'
        )

    colour = {"A": "#2e7d32", "B": "#2e7d32", "C": "#e08600", "D": "#c62828", "F": "#7c2d92"}.get(
        report.grade, "#5c5c5c"
    )
    summary = report.summary or {}
    counts = " &middot; ".join(
        f"{summary.get(key, 0)} {label}"
        for key, label in (
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("unknown", "unchecked"),
            ("passed", "passed"),
        )
    )

    rows = []
    for finding in report.findings:
        if finding.status is Status.PASS:
            continue
        evidence = (
            f'<div class="evidence">{html.escape(finding.evidence)}</div>' if finding.evidence else ""
        )
        recommendation = (
            f'<div class="rec">{html.escape(finding.recommendation)}</div>'
            if finding.recommendation
            else ""
        )
        rows.append(
            f'<tr><td class="sev {finding.severity.value}">{finding.severity.value}</td>'
            f"<td><strong>{html.escape(finding.title)}</strong>{evidence}{recommendation}</td></tr>"
        )

    if not rows:
        rows.append('<tr><td colspan="2">No issues were found by this scan.</td></tr>')

    wordpress = (
        f"WordPress {html.escape(report.wordpress_version or 'version unknown')}, "
        f"{len(report.components)} component(s)"
        if report.is_wordpress
        else "WordPress not detected"
    )

    return f"""<div class="site">
  <h2>{site}</h2>
  <div><span class="grade" style="background:{colour}">{report.grade}</span>
       &nbsp;{report.score}/100 &middot; {wordpress}</div>
  <div class="counts">{counts}</div>
  <table>{"".join(rows)}</table>
</div>"""
