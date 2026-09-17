"""The vulnerability database: parsing the feeds, and matching versions against them.

This is where a bug is most expensive in both directions. A missed match tells an MSP a site is
fine when a public exploit covers it. A wrong match sends them to a customer with an emergency that
does not exist -- and after the second false alarm nobody reads the reports any more. The range
boundaries below are where both live: `to_inclusive` decides whether the version that *fixed* a
vulnerability is reported as still having it.
"""

from __future__ import annotations

import json

import pytest
import requests

from wpaudit.vulndb.sources import FeedAuthError, VulnRecord, WordfenceSource, WPScanSource
from wpaudit.vulndb.store import VulnerabilityDatabase


class TestWordfenceParsing:
    def test_reads_every_advisory_in_the_feed(self, wordfence_feed):
        records = list(WordfenceSource.parse(wordfence_feed))
        assert len(records) == 5

    def test_keeps_the_details_a_report_needs(self, wordfence_feed):
        record = next(
            r for r in WordfenceSource.parse(wordfence_feed) if r.cve == "CVE-2023-6449"
        )
        assert record.software_type == "plugin"
        assert record.slug == "contact-form-7"
        assert record.cvss_score == 9.8
        assert record.patched_in == "5.7.2"
        assert record.to_version == "5.7.1"
        assert record.to_inclusive is True
        assert record.references

    def test_normalises_core_advisories(self, wordfence_feed):
        record = next(r for r in WordfenceSource.parse(wordfence_feed) if r.software_type == "core")
        assert record.slug == "wordpress"

    def test_accepts_a_list_shaped_feed(self, wordfence_feed):
        # Wordfence has changed the envelope before; the records are what matter.
        as_list = list(wordfence_feed.values())
        assert len(list(WordfenceSource.parse(as_list))) == 5

    def test_skips_junk_without_losing_the_rest(self):
        feed = {
            "good": {
                "id": "good",
                "title": "Real advisory",
                "software": [
                    {"type": "plugin", "slug": "x", "affected_versions": {"a": {"to_version": "1.0"}}}
                ],
            },
            "no-id": {"title": "Missing an id"},
            "not-a-dict": "nonsense",
            "no-software": {"id": "empty", "title": "No software list"},
        }
        records = list(WordfenceSource.parse(feed))
        assert [r.vuln_id for r in records] == ["good"]

    def test_records_an_advisory_with_no_version_range(self):
        # Dropping it would lose the advisory silently; an unbounded range is noisy but visible.
        feed = {
            "a": {
                "id": "a",
                "title": "No range given",
                "software": [{"type": "plugin", "slug": "mystery", "affected_versions": {}}],
            }
        }
        record = next(WordfenceSource.parse(feed))
        assert record.from_version == "*"
        assert record.to_version == "*"

    def test_returns_nothing_for_an_unrecognised_payload(self):
        assert list(WordfenceSource.parse("not json at all")) == []
        assert list(WordfenceSource.parse(None)) == []


class TestWPScanParsing:
    PAYLOAD = json.loads(
        """
        {
          "contact-form-7": {
            "latest_version": "5.9.0",
            "vulnerabilities": [
              {
                "id": "1234-abcd",
                "title": "Contact Form 7 < 5.7.2 - Arbitrary File Upload",
                "fixed_in": "5.7.2",
                "cvss": {"score": "9.8"},
                "published_date": "2023-12-11T00:00:00.000Z",
                "references": {"cve": ["2023-6449"], "url": ["https://example.org/advisory"]}
              }
            ]
          }
        }
        """
    )

    def test_reads_an_advisory(self):
        records = list(WPScanSource.parse(self.PAYLOAD, "plugin", "contact-form-7"))
        assert len(records) == 1
        record = records[0]
        assert record.cve == "CVE-2023-6449"
        assert record.cvss_score == 9.8
        assert record.patched_in == "5.7.2"

    def test_treats_fixed_in_as_an_exclusive_upper_bound(self):
        # WPScan states the version a fix landed in, not a range. Reporting the fixed version
        # itself as vulnerable is the classic false positive here.
        record = next(WPScanSource.parse(self.PAYLOAD, "plugin", "contact-form-7"))
        assert record.to_version == "5.7.2"
        assert record.to_inclusive is False

    def test_requires_a_token(self):
        with pytest.raises(ValueError):
            WPScanSource("")


class TestMatching:
    def test_matches_a_vulnerable_version(self, vulndb):
        # 5.7.0 is inside the "<= 5.7.1" advisory but past the "<= 5.6.0" one, so exactly one of
        # the two Contact Form 7 entries applies.
        matches = vulndb.match("plugin", "contact-form-7", "5.7.0")
        assert [m.cve for m in matches] == ["CVE-2023-6449"]

    def test_matches_every_advisory_that_covers_the_version(self, vulndb):
        assert [m.cve for m in vulndb.match("plugin", "contact-form-7", "5.5.0")] == [
            "CVE-2023-6449",
            "CVE-2022-0003",
        ]

    def test_orders_the_worst_first(self, vulndb):
        matches = vulndb.match("plugin", "contact-form-7", "5.5.0")
        assert matches[0].cvss_score == 9.8

    def test_does_not_match_a_patched_version(self, vulndb):
        assert vulndb.match("plugin", "contact-form-7", "5.7.2") == []

    def test_includes_the_upper_bound_when_the_feed_says_inclusive(self, vulndb):
        # "<= 5.7.1" means 5.7.1 is affected. Getting this wrong understates a real exposure.
        assert vulndb.match("plugin", "contact-form-7", "5.7.1")

    def test_respects_a_lower_bound(self, vulndb):
        # WooCommerce is only affected from 8.0.0 on; 7.9.0 predates the bug.
        assert vulndb.match("plugin", "woocommerce", "7.9.0") == []
        assert vulndb.match("plugin", "woocommerce", "8.1.0")

    def test_matches_core_separately_from_plugins(self, vulndb):
        assert vulndb.match("core", "wordpress", "6.3.1")
        assert vulndb.match("core", "wordpress", "6.4.2") == []
        assert vulndb.match("plugin", "wordpress", "6.3.1") == []

    def test_matches_themes(self, vulndb):
        assert vulndb.match("theme", "twentytwentythree", "1.0")
        assert vulndb.match("theme", "twentytwentythree", "1.1") == []

    def test_is_case_insensitive_about_slugs(self, vulndb):
        assert vulndb.match("plugin", "Contact-Form-7", "5.7.0")

    def test_returns_nothing_without_a_version(self, vulndb):
        # No version means no match to make. The caller reports that as unknown, not as clean.
        assert vulndb.match("plugin", "contact-form-7", None) == []
        assert vulndb.match("plugin", "contact-form-7", "") == []

    def test_returns_nothing_for_an_unknown_component(self, vulndb):
        assert vulndb.match("plugin", "some-bespoke-plugin", "1.0") == []

    def test_reports_one_advisory_once_even_with_several_ranges(self, tmp_path):
        database = VulnerabilityDatabase(tmp_path / "db.sqlite")
        ranges = [
            VulnRecord(
                source="test",
                vuln_id="same-id",
                software_type="plugin",
                slug="x",
                title="Two ranges, one advisory",
                from_version="*",
                to_version="2.0",
                to_inclusive=True,
            ),
            VulnRecord(
                source="test",
                vuln_id="same-id",
                software_type="plugin",
                slug="x",
                title="Two ranges, one advisory",
                from_version="1.0",
                to_version="3.0",
                to_inclusive=True,
            ),
        ]
        database.replace_source("test", ranges)
        assert len(database.match("plugin", "x", "1.5")) == 1
        database.close()


class TestStore:
    def test_reports_what_it_holds(self, vulndb):
        info = vulndb.info()
        assert info.exists
        assert info.record_count == 5
        assert info.component_count == 4
        assert info.sources == ["wordfence"]
        assert "CC BY-SA" in info.attribution

    def test_reports_an_empty_database_rather_than_failing(self, tmp_path):
        database = VulnerabilityDatabase(tmp_path / "missing.sqlite")
        info = database.info()
        assert info.exists is False
        assert database.is_stale() is True

    def test_an_update_replaces_the_previous_data(self, vulndb, wordfence_feed):
        # A withdrawn advisory must not live forever in somebody's cache.
        shrunk = {"only": next(iter(wordfence_feed.values()))}
        vulndb.replace_source("wordfence", WordfenceSource.parse(shrunk))
        assert vulndb.info().record_count == 1

    def test_sources_do_not_overwrite_each_other(self, vulndb):
        vulndb.replace_source(
            "wpscan",
            [
                VulnRecord(
                    source="wpscan",
                    vuln_id="w-1",
                    software_type="plugin",
                    slug="contact-form-7",
                    title="From WPScan",
                    to_version="6.0",
                    to_inclusive=False,
                )
            ],
        )
        matches = vulndb.match("plugin", "contact-form-7", "5.7.0")
        assert {m.source for m in matches} == {"wordfence", "wpscan"}

    def test_freshness_is_part_of_the_answer(self, vulndb):
        # A scan against a three-month-old database is not a clean bill of health, so the age has
        # to travel with the result rather than being assumed current.
        info = vulndb.info()
        assert info.updated_at
        assert info.age_hours is not None
        assert vulndb.is_stale(max_age_hours=24) is False


class TestWordfenceV3Access:
    """v3 of the feed needs a token. Getting this wrong makes every update fail silently-ish."""

    class FakeResponse:
        def __init__(self, status_code=200, payload=None):
            self.status_code = status_code
            self._payload = payload if payload is not None else {}
            self.reason = "OK" if status_code < 400 else "Error"
            self.text = ""

        def json(self):
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.exceptions.HTTPError(f"{self.status_code}")

    def capture(self, monkeypatch, response=None):
        captured = {}

        def fake_get(url, timeout=None, headers=None):
            captured["url"] = url
            captured["headers"] = headers or {}
            return response or self.FakeResponse()

        monkeypatch.setattr(requests, "get", fake_get)
        return captured

    def test_defaults_to_v3_scanner(self):
        assert WordfenceSource().url == (
            "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner"
        )

    def test_builds_the_production_url(self):
        assert WordfenceSource(variant="production").url.endswith("/v3/vulnerabilities/production")

    def test_v2_is_still_selectable_for_the_grace_period(self):
        source = WordfenceSource(version="v2")
        assert "/v2/vulnerabilities/scanner" in source.url
        assert source.needs_token is False

    def test_rejects_an_unknown_version_or_variant(self):
        with pytest.raises(ValueError):
            WordfenceSource(version="v9")
        with pytest.raises(ValueError):
            WordfenceSource(variant="everything")

    def test_sends_the_token_as_a_bearer_header(self, monkeypatch):
        captured = self.capture(monkeypatch)
        WordfenceSource(token="abc123").fetch()
        assert captured["headers"]["Authorization"] == "Bearer abc123"

    def test_reads_the_token_from_the_environment(self, monkeypatch):
        # Preferred over a flag: a token on the command line is visible in the process list.
        monkeypatch.setenv("WORDFENCE_API_TOKEN", "from-env")
        captured = self.capture(monkeypatch)
        WordfenceSource().fetch()
        assert captured["headers"]["Authorization"] == "Bearer from-env"

    def test_an_explicit_token_wins_over_the_environment(self, monkeypatch):
        monkeypatch.setenv("WORDFENCE_API_TOKEN", "from-env")
        captured = self.capture(monkeypatch)
        WordfenceSource(token="explicit").fetch()
        assert captured["headers"]["Authorization"] == "Bearer explicit"

    def test_refuses_v3_without_a_token_and_says_where_to_get_one(self, monkeypatch):
        monkeypatch.delenv("WORDFENCE_API_TOKEN", raising=False)
        with pytest.raises(FeedAuthError) as excinfo:
            WordfenceSource().fetch()
        message = str(excinfo.value)
        assert "Integrations" in message
        assert "WORDFENCE_API_TOKEN" in message

    def test_v2_needs_no_token(self, monkeypatch):
        monkeypatch.delenv("WORDFENCE_API_TOKEN", raising=False)
        captured = self.capture(monkeypatch)
        WordfenceSource(version="v2").fetch()
        assert "Authorization" not in captured["headers"]

    @pytest.mark.parametrize("status", [401, 403])
    def test_a_rejected_token_is_not_reported_as_a_network_fault(self, monkeypatch, status):
        # The two look identical from the outside and need completely different fixes.
        self.capture(monkeypatch, self.FakeResponse(status))
        with pytest.raises(FeedAuthError) as excinfo:
            WordfenceSource(token="stale").fetch()
        assert str(status) in str(excinfo.value)
        assert "token" in str(excinfo.value).lower()

    def test_other_http_errors_still_raise_normally(self, monkeypatch):
        self.capture(monkeypatch, self.FakeResponse(500))
        with pytest.raises(requests.exceptions.HTTPError):
            WordfenceSource(token="fine").fetch()

    def test_an_explicit_url_overrides_the_version_and_variant(self):
        source = WordfenceSource("https://mirror.example/feed.json", token="x")
        assert source.url == "https://mirror.example/feed.json"

    def test_identifies_itself_in_the_user_agent(self, monkeypatch):
        captured = self.capture(monkeypatch)
        WordfenceSource(token="x").fetch()
        assert "wp-audit" in captured["headers"]["User-Agent"]
