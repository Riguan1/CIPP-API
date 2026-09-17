"""Getting a change in front of a human.

Two paths, deliberately:

**Printing it.** `--only-changes` prints nothing at all when nothing changed, which makes the
oldest notification system in the world work perfectly -- cron mails you whatever the job printed,
so a silent job sends no mail and a changed site does. No credentials, no integration, nothing to
keep working.

**Posting it.** A webhook for teams that live in Teams or Slack. The payload is built once and
wrapped per destination, so the message says the same thing everywhere.

There is deliberately no SMTP client here. It would mean this tool holding a password, and the
machine already has a way to send mail that is configured, monitored and allowed through the
firewall.
"""

from __future__ import annotations

import json
from typing import Any

import requests

from .diff import ScanDiff, summarise

WEBHOOK_FORMATS = ("json", "slack", "teams")


def build_payload(
    diffs: list[ScanDiff],
    *,
    feed_alert_text: str = "",
    feed_alert_count: int = 0,
) -> dict[str, Any]:
    summary = summarise(diffs)
    summary["feed_alerts"] = feed_alert_count
    return {
        "source": "wp-audit",
        "summary": summary,
        "text": render_summary_text(diffs, feed_alert_text=feed_alert_text),
        "sites": [diff.to_dict() for diff in diffs if diff.has_changes and not diff.first_scan],
    }


def render_summary_text(diffs: list[ScanDiff], *, feed_alert_text: str = "") -> str:
    """One readable block covering every site that changed."""
    blocks: list[str] = []

    for diff in diffs:
        if diff.first_scan or not diff.has_changes:
            continue

        header = f"{diff.site}: {diff.previous_grade} -> {diff.current_grade}"
        delta = diff.score_delta
        if delta is not None and delta != 0:
            header += f" ({diff.current_score}/100, {delta:+d})"
        lines = [header]

        if diff.became_unreachable:
            lines.append("  ! the site could not be reached this time")
        if diff.became_reachable:
            lines.append("  + the site is reachable again")

        for vulnerability in diff.new_vulnerabilities:
            name = vulnerability.get("cve") or vulnerability.get("title") or "advisory"
            fix = vulnerability.get("patched_in")
            lines.append(
                f"  ! new vulnerability on {vulnerability.get('component')} "
                f"{vulnerability.get('version') or ''}: {name}"
                + (f" (fixed in {fix})" if fix else "")
            )
        for change in diff.regressions:
            lines.append(f"  ! new {change.severity.lower()}: {change.title}")
        for vulnerability in diff.resolved_vulnerabilities:
            name = vulnerability.get("cve") or vulnerability.get("title") or "advisory"
            lines.append(f"  + resolved on {vulnerability.get('component')}: {name}")
        for change in diff.improvements:
            lines.append(f"  + fixed: {change.title}")

        blocks.append("\n".join(lines))

    if feed_alert_text:
        blocks.append(feed_alert_text)

    return "\n\n".join(blocks)


def _headline(payload: dict[str, Any]) -> str:
    """A one-line summary, tolerant of a payload that did not come from build_payload."""
    summary = payload.get("summary") or {}
    if not summary:
        return "wp-audit notification"
    return (
        f"{summary.get('sites_changed', 0)} of {summary.get('sites_scanned', 0)} site(s) changed - "
        f"{summary.get('new_findings', 0)} new, {summary.get('resolved_findings', 0)} resolved"
    )


def to_slack(payload: dict[str, Any]) -> dict[str, Any]:
    headline = f"wp-audit: {_headline(payload)}"
    body = payload.get("text") or ""
    return {
        "text": headline,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{headline}*"}},
            {
                "type": "section",
                # Slack truncates a block past 3000 characters, and a truncated JSON block is
                # rejected outright rather than shortened.
                "text": {"type": "mrkdwn", "text": f"```{body[:2800]}```"},
            },
        ],
    }


def to_teams(payload: dict[str, Any]) -> dict[str, Any]:
    """An Adaptive Card, which is what a Teams Workflows webhook accepts.

    Not a MessageCard: the Office 365 connectors those relied on have been retired, so a Workflows
    URL ("When a Teams webhook request is received") is the supported way in.
    """
    headline = _headline(payload)
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": "wp-audit"},
                        {"type": "TextBlock", "text": headline, "wrap": True},
                        {
                            "type": "TextBlock",
                            "text": (payload.get("text") or "")[:4000],
                            "wrap": True,
                            "fontType": "Monospace",
                        },
                    ],
                },
            }
        ],
    }


def wrap(payload: dict[str, Any], fmt: str) -> dict[str, Any]:
    if fmt == "slack":
        return to_slack(payload)
    if fmt == "teams":
        return to_teams(payload)
    return payload


def send_webhook(
    url: str, payload: dict[str, Any], fmt: str = "json", *, timeout: float = 15.0
) -> tuple[bool, str]:
    """Post a payload. Returns (delivered, error).

    Never raises: a scan that found something must not be lost because the chat tool was down. The
    caller reports the delivery failure and the findings are still on stdout and in the history.
    """
    if fmt not in WEBHOOK_FORMATS:
        return False, f"Unknown webhook format '{fmt}'."
    try:
        response = requests.post(
            url,
            data=json.dumps(wrap(payload, fmt)),
            headers={"Content-Type": "application/json", "User-Agent": "wp-audit/1.0"},
            timeout=timeout,
        )
        if response.status_code >= 400:
            return False, f"{response.status_code} {response.reason}: {response.text[:200]}"
        return True, ""
    except requests.exceptions.RequestException as exc:
        return False, str(exc)
    except Exception as exc:
        # The promise this function makes to its callers is that it never raises. A malformed
        # payload must not take down a scan that already found something worth reporting.
        return False, f"Could not build or send the notification: {exc}"
