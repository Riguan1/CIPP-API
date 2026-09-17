"""Feed-update alerts and notification payloads.

`update --alert-known` answers the question a daily feed download exists for: does today's data
affect a plugin one of my customers runs. It is the one check that covers a site *between* scans,
so the property that matters is that it reports what is new to these sites -- not everything that
matches them, which after the first run would be the same alert every night until someone stopped
reading it.
"""

from __future__ import annotations

import json

from test_history import component_with_vuln, make_report

from wpaudit.alerts import group_by_site, match_inventory, new_matches, render_feed_alert
from wpaudit.diff import compare
from wpaudit.history import ScanHistory
from wpaudit.models import Component
from wpaudit.notify import build_payload, render_summary_text, to_slack, to_teams, wrap
from wpaudit.vulndb.sources import VulnRecord, WordfenceSource
from wpaudit.vulndb.store import VulnerabilityDatabase


def seeded_history(tmp_path, *, version="5.7.0", core="6.3.1") -> ScanHistory:
    history = ScanHistory(tmp_path / "history.sqlite")
    history.record(
        make_report(
            url="https://klant.nl/",
            version=core,
            components=[Component(kind="plugin", slug="contact-form-7", version=version)],
        )
    )
    return history


class TestInventoryMatching:
    def test_matches_the_components_a_site_was_seen_running(self, tmp_path, vulndb):
        history = seeded_history(tmp_path)
        matches = match_inventory(vulndb, history)

        slugs = {(m.site, m.slug) for m in matches}
        assert ("klant.nl", "contact-form-7") in slugs
        # Core is matched from the same inventory, not only plugins.
        assert ("klant.nl", "wordpress") in slugs
        history.close()

    def test_ignores_a_component_with_no_known_version(self, tmp_path, vulndb):
        history = ScanHistory(tmp_path / "h.sqlite")
        history.record(
            make_report(version=None, components=[Component(kind="plugin", slug="contact-form-7")])
        )
        assert match_inventory(vulndb, history) == []
        history.close()

    def test_reports_nothing_without_a_database(self, tmp_path):
        history = seeded_history(tmp_path)
        empty = VulnerabilityDatabase(tmp_path / "missing.sqlite")
        assert match_inventory(empty, history) == []
        history.close()
        empty.close()

    def test_new_matches_are_only_the_ones_that_were_not_there_before(self, tmp_path, vulndb, wordfence_feed):
        history = seeded_history(tmp_path)
        before = match_inventory(vulndb, history)

        # A feed update that adds one advisory against a plugin this customer runs.
        extra = dict(wordfence_feed)
        extra["new-one"] = {
            "id": "new-one",
            "title": "Contact Form 7 <= 5.8.0 - Newly published issue",
            "software": [
                {
                    "type": "plugin",
                    "slug": "contact-form-7",
                    "affected_versions": {
                        "* - 5.8.0": {
                            "from_version": "*",
                            "from_inclusive": True,
                            "to_version": "5.8.0",
                            "to_inclusive": True,
                        }
                    },
                    "patched": True,
                    "patched_versions": ["5.8.1"],
                }
            ],
            "cve": "CVE-2026-1111",
            "cvss": {"score": 8.8, "rating": "High"},
        }
        vulndb.replace_source("wordfence", WordfenceSource.parse(extra))

        fresh = new_matches(before, match_inventory(vulndb, history))
        assert [m.match.cve for m in fresh] == ["CVE-2026-1111"]
        assert fresh[0].site == "klant.nl"
        history.close()

    def test_an_update_that_changes_nothing_for_these_sites_is_silent(self, tmp_path, vulndb, wordfence_feed):
        # Otherwise the nightly job alerts every night with the same advisories and gets filtered.
        history = seeded_history(tmp_path)
        before = match_inventory(vulndb, history)
        vulndb.replace_source("wordfence", WordfenceSource.parse(wordfence_feed))

        assert new_matches(before, match_inventory(vulndb, history)) == []
        history.close()

    def test_orders_the_worst_first(self, tmp_path, vulndb):
        history = seeded_history(tmp_path)
        after = match_inventory(vulndb, history)
        fresh = new_matches([], after)
        scores = [m.match.cvss_score or 0 for m in fresh]
        assert scores == sorted(scores, reverse=True)
        history.close()


class TestFeedAlertRendering:
    def test_names_the_site_the_component_and_the_fix(self, tmp_path, vulndb):
        history = seeded_history(tmp_path)
        text = render_feed_alert(new_matches([], match_inventory(vulndb, history)))

        assert "klant.nl" in text
        assert "contact-form-7" in text
        assert "CVE-2023-6449" in text
        assert "fixed in 5.7.2" in text
        # The caveat has to travel with the alert: this is the last known inventory, not a re-scan.
        assert "Re-scan" in text
        history.close()

    def test_renders_nothing_when_there_is_nothing(self):
        assert render_feed_alert([]) == ""

    def test_groups_by_site(self, tmp_path, vulndb):
        history = seeded_history(tmp_path)
        history.record(
            make_report(
                url="https://andere-klant.nl/",
                components=[Component(kind="plugin", slug="contact-form-7", version="5.7.0")],
            )
        )
        grouped = group_by_site(new_matches([], match_inventory(vulndb, history)))
        assert set(grouped) == {"klant.nl", "andere-klant.nl"}
        history.close()


class TestNotificationPayloads:
    def diffs(self):
        before = make_report(components=[Component(kind="plugin", slug="contact-form-7", version="5.7.0")])
        after = make_report(score=55, grade="D", components=[component_with_vuln()])
        return [compare(before.to_dict(), after, site="klant.nl")]

    def test_summary_text_names_what_changed(self):
        text = render_summary_text(self.diffs())
        assert "klant.nl" in text
        assert "CVE-2023-6449" in text
        assert "fixed in 5.7.2" in text

    def test_summary_text_is_empty_when_nothing_changed(self):
        # This emptiness is the notification mechanism for a cron job.
        report = make_report()
        assert render_summary_text([compare(report.to_dict(), report, site="klant.nl")]) == ""

    def test_payload_carries_counts_and_detail(self):
        payload = build_payload(self.diffs())
        assert payload["summary"]["sites_changed"] == 1
        assert payload["summary"]["new_vulnerabilities"] == 1
        assert payload["sites"][0]["site"] == "klant.nl"

    def test_slack_payload_is_within_block_limits(self):
        # Slack rejects a block over 3000 characters outright rather than truncating it.
        many = self.diffs() * 40
        block = to_slack(build_payload(many))["blocks"][1]["text"]["text"]
        assert len(block) < 3000
        assert json.dumps(to_slack(build_payload(many)))

    def test_teams_payload_is_an_adaptive_card(self):
        # Office 365 connectors (MessageCard) have been retired; Workflows take Adaptive Cards.
        card = to_teams(build_payload(self.diffs()))
        assert card["type"] == "message"
        assert card["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
        assert card["attachments"][0]["content"]["type"] == "AdaptiveCard"

    def test_json_format_passes_the_payload_through(self):
        payload = build_payload(self.diffs())
        assert wrap(payload, "json") is payload

    def test_feed_alerts_ride_along_in_the_payload(self):
        payload = build_payload([], feed_alert_text="two new advisories", feed_alert_count=2)
        assert payload["summary"]["feed_alerts"] == 2
        assert "two new advisories" in payload["text"]


class TestWebhookDelivery:
    def test_reports_a_failed_delivery_instead_of_raising(self, monkeypatch):
        # A scan that found something must not be lost because the chat tool was down.
        import requests

        from wpaudit.notify import send_webhook

        def explode(*args, **kwargs):
            raise requests.exceptions.ConnectionError("no route to host")

        monkeypatch.setattr(requests, "post", explode)
        delivered, error = send_webhook("https://hooks.example/x", {"text": "hi"})
        assert delivered is False
        assert "no route" in error

    def test_rejects_an_unknown_format(self):
        from wpaudit.notify import send_webhook

        delivered, error = send_webhook("https://hooks.example/x", {}, "carrier-pigeon")
        assert delivered is False
        assert "format" in error

    def test_posts_the_wrapped_payload(self, monkeypatch):
        import requests

        from wpaudit.notify import send_webhook

        captured = {}

        class Response:
            status_code = 200
            reason = "OK"
            text = ""

        def capture(url, data=None, headers=None, timeout=None):
            captured["url"] = url
            captured["body"] = json.loads(data)
            return Response()

        monkeypatch.setattr(requests, "post", capture)
        delivered, error = send_webhook("https://hooks.example/x", {"text": "hello"}, "slack")
        assert delivered is True
        assert error == ""
        assert "blocks" in captured["body"]


class TestVulnRecordRoundTrip:
    def test_a_record_survives_the_database(self, tmp_path):
        database = VulnerabilityDatabase(tmp_path / "db.sqlite")
        database.replace_source(
            "test",
            [
                VulnRecord(
                    source="test",
                    vuln_id="v1",
                    software_type="plugin",
                    slug="x",
                    title="Something",
                    cve="CVE-2026-0001",
                    cvss_score=7.5,
                    patched_versions=["2.0"],
                    references=["https://example.org/a", "https://example.org/b"],
                    to_version="1.9",
                    to_inclusive=True,
                )
            ],
        )
        match = database.match("plugin", "x", "1.0")[0]
        assert match.cve == "CVE-2026-0001"
        assert match.cvss_score == 7.5
        assert match.patched_in == "2.0"
        assert match.references == ["https://example.org/a", "https://example.org/b"]
        database.close()
