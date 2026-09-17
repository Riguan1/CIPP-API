"""Scan history and the diff between two scans.

The diff is what turns a recurring scan into something anyone reads, so its failure modes are
alerts people learn to ignore. Two cases matter most: a check that could not run this time must
never be reported as "fixed", and a site that went unreachable must never look like a site whose
problems all went away at once.
"""

from __future__ import annotations

from wpaudit.diff import Snapshot, compare, summarise
from wpaudit.history import ScanHistory, site_key
from wpaudit.models import Component, Finding, ScanReport, Severity, Status, VulnerabilityMatch


def make_report(
    url="https://klant.nl/",
    *,
    findings=None,
    score=80,
    grade="B",
    completed=True,
    components=None,
    version="6.4.2",
    scanned_at="2026-01-01T00:00:00+00:00",
) -> ScanReport:
    return ScanReport(
        url=url,
        final_url=url,
        scanned_at=scanned_at,
        completed=completed,
        is_wordpress=True,
        wordpress_version=version,
        score=score,
        grade=grade,
        findings=findings or [],
        components=components or [],
    )


def finding(id_, status=Status.FAIL, severity=Severity.MEDIUM, title=None) -> Finding:
    return Finding(
        id=id_,
        category="Test",
        title=title or id_,
        severity=severity,
        status=status,
        evidence="e",
        recommendation="r",
    )


def component_with_vuln(slug="contact-form-7", version="5.7.0", cve="CVE-2023-6449") -> Component:
    return Component(
        kind="plugin",
        slug=slug,
        version=version,
        vulnerabilities=[
            VulnerabilityMatch(
                source="wordfence",
                vuln_id=cve,
                title=f"{slug} vulnerability",
                cve=cve,
                cvss_score=9.8,
                patched_in="5.7.2",
            )
        ],
    )


class TestSiteKey:
    def test_uses_the_hostname_so_history_survives_a_redirect_change(self):
        # A site that starts redirecting to www, or gains HTTPS, is still the same customer site;
        # forking its history the day that happens would lose the trend.
        assert site_key("http://klant.nl/") == "klant.nl"
        assert site_key("https://klant.nl/some/page") == "klant.nl"
        assert site_key("klant.nl") == "klant.nl"

    def test_lowercases(self):
        assert site_key("https://KLANT.NL/") == "klant.nl"


class TestHistory:
    def test_records_and_returns_the_previous_scan(self, tmp_path):
        history = ScanHistory(tmp_path / "h.sqlite")
        history.record(make_report(score=70))
        history.record(make_report(score=90))

        previous = history.previous("klant.nl")
        # The most recent stored scan is what the next one is compared against.
        assert previous["score"] == 90
        history.close()

    def test_keeps_a_component_inventory_for_feed_alerts(self, tmp_path):
        history = ScanHistory(tmp_path / "h.sqlite")
        history.record(make_report(components=[component_with_vuln()]))

        components = history.components()
        assert [(c.site, c.slug, c.version) for c in components] == [
            ("klant.nl", "contact-form-7", "5.7.0")
        ]
        assert history.cores() == [("klant.nl", "6.4.2")]
        history.close()

    def test_updates_a_component_version_rather_than_duplicating_it(self, tmp_path):
        history = ScanHistory(tmp_path / "h.sqlite")
        history.record(make_report(components=[component_with_vuln(version="5.7.0")]))
        history.record(make_report(components=[component_with_vuln(version="5.9.0")]))

        components = history.components()
        assert len(components) == 1
        assert components[0].version == "5.9.0"
        history.close()

    def test_stores_a_failed_scan_but_does_not_compare_against_it(self, tmp_path):
        # "Unreachable for four days" is worth seeing in the trend, but diffing against a scan that
        # never reached the site would report every finding as newly resolved.
        history = ScanHistory(tmp_path / "h.sqlite")
        history.record(make_report(score=80))
        history.record(make_report(completed=False, score=0, grade="F"))

        assert len(history.trend("klant.nl")) == 2
        assert history.previous("klant.nl")["score"] == 80
        history.close()

    def test_prunes_old_scans(self, tmp_path):
        history = ScanHistory(tmp_path / "h.sqlite")
        for index in range(10):
            history.record(make_report(scanned_at=f"2026-01-{index + 1:02d}T00:00:00+00:00"))

        history.prune(keep_per_site=3)
        assert len(history.trend("klant.nl", limit=99)) == 3
        history.close()

    def test_separates_sites(self, tmp_path):
        history = ScanHistory(tmp_path / "h.sqlite")
        history.record(make_report(url="https://a.nl/"))
        history.record(make_report(url="https://b.nl/"))
        assert history.sites() == ["a.nl", "b.nl"]
        history.close()


class TestDiff:
    def test_a_first_scan_is_not_a_pile_of_regressions(self):
        # Otherwise adding a customer alerts on everything they have ever had wrong.
        diff = compare(None, make_report(findings=[finding("A")]))
        assert diff.first_scan is True
        assert diff.regressions == []
        assert diff.has_changes is False

    def test_reports_a_new_finding(self):
        before = make_report(findings=[finding("A", Status.PASS)]).to_dict()
        after = make_report(findings=[finding("A", Status.FAIL)])
        diff = compare(before, after)

        assert [c.finding_id for c in diff.regressions] == ["A"]
        assert diff.improvements == []

    def test_reports_a_resolved_finding(self):
        before = make_report(findings=[finding("A", Status.FAIL)]).to_dict()
        after = make_report(findings=[finding("A", Status.PASS)])
        diff = compare(before, after)

        assert [c.finding_id for c in diff.improvements] == ["A"]
        assert diff.regressions == []

    def test_a_finding_that_appears_from_nowhere_is_a_regression(self):
        # Exposure checks only emit a finding when something is there, so "absent" is the pass.
        before = make_report(findings=[]).to_dict()
        after = make_report(findings=[finding("WP-CONFIG-BACKUP", Status.FAIL, Severity.CRITICAL)])
        assert [c.finding_id for c in compare(before, after).regressions] == ["WP-CONFIG-BACKUP"]

    def test_an_unchecked_finding_is_not_a_change_in_either_direction(self):
        # UNKNOWN means the scanner could not see it. Treating that as fixed would report good
        # news that nobody earned; treating it as new would alert every time a site is slow.
        before = make_report(findings=[finding("A", Status.FAIL)]).to_dict()
        after = make_report(findings=[finding("A", Status.UNKNOWN)])
        diff = compare(before, after)
        assert diff.regressions == []
        assert diff.improvements == []

    def test_a_skipped_check_group_is_not_a_pile_of_fixes(self):
        # --skip-exposure makes every exposure finding vanish from the report. Reading that as
        # "they fixed the exposed wp-config backup" would be the most damaging false good news
        # this tool could produce.
        before = make_report(
            findings=[Finding("WP-CONFIG-BACKUP", "Exposure", "backup", Severity.CRITICAL, Status.FAIL)]
        ).to_dict()
        after = make_report(findings=[])
        after.skipped = ["Exposure", "Enumeration"]

        diff = compare(before, after)
        assert diff.improvements == []
        assert diff.has_changes is False

    def test_a_finding_that_really_went_away_still_counts_as_fixed(self):
        # The counterpart: when the group did run, an absent finding means the file is gone.
        before = make_report(
            findings=[Finding("WP-CONFIG-BACKUP", "Exposure", "backup", Severity.CRITICAL, Status.FAIL)]
        ).to_dict()
        diff = compare(before, make_report(findings=[]))
        assert [c.finding_id for c in diff.improvements] == ["WP-CONFIG-BACKUP"]

    def test_a_warning_counts_as_open(self):
        before = make_report(findings=[finding("A", Status.PASS)]).to_dict()
        after = make_report(findings=[finding("A", Status.WARN)])
        assert [c.finding_id for c in compare(before, after).regressions] == ["A"]

    def test_tracks_the_score(self):
        before = make_report(score=60, grade="D").to_dict()
        after = make_report(score=85, grade="B")
        diff = compare(before, after)
        assert diff.score_delta == 25
        assert (diff.previous_grade, diff.current_grade) == ("D", "B")

    def test_reports_a_newly_published_vulnerability(self):
        before = make_report(components=[Component(kind="plugin", slug="contact-form-7", version="5.7.0")]).to_dict()
        after = make_report(components=[component_with_vuln()])
        diff = compare(before, after)

        assert len(diff.new_vulnerabilities) == 1
        assert diff.new_vulnerabilities[0]["cve"] == "CVE-2023-6449"

    def test_reports_a_vulnerability_that_went_away(self):
        before = make_report(components=[component_with_vuln()]).to_dict()
        after = make_report(components=[Component(kind="plugin", slug="contact-form-7", version="5.7.2")])
        diff = compare(before, after)

        assert len(diff.resolved_vulnerabilities) == 1
        assert diff.new_vulnerabilities == []

    def test_tracks_one_advisory_of_several_on_the_same_component(self):
        # The component's finding persists either way, so tracking by finding id alone would miss
        # a second CVE being published against a plugin that already had one.
        before = make_report(components=[component_with_vuln(cve="CVE-1")]).to_dict()
        second = component_with_vuln(cve="CVE-1")
        second.vulnerabilities.append(
            VulnerabilityMatch(source="wordfence", vuln_id="CVE-2", title="second", cve="CVE-2")
        )
        diff = compare(before, make_report(components=[second]))

        assert [v["cve"] for v in diff.new_vulnerabilities] == ["CVE-2"]

    def test_an_unreachable_site_is_reported_as_such_not_as_fixed(self):
        # The dangerous false good-news: every finding disappears because nothing was checked.
        before = make_report(findings=[finding("A", Status.FAIL), finding("B", Status.FAIL)]).to_dict()
        after = make_report(completed=False, findings=[])
        diff = compare(before, after)

        assert diff.became_unreachable is True
        assert diff.improvements == []
        assert diff.has_changes is True

    def test_a_site_coming_back_is_reported(self):
        before = make_report(completed=False).to_dict()
        after = make_report()
        assert compare(before, after).became_reachable is True

    def test_identical_scans_produce_nothing(self):
        # The silence that makes a nightly cron usable.
        findings = [finding("A", Status.FAIL), finding("B", Status.PASS)]
        before = make_report(findings=findings).to_dict()
        assert compare(before, make_report(findings=findings)).has_changes is False

    def test_names_the_worst_new_severity_for_a_headline(self):
        before = make_report(findings=[]).to_dict()
        after = make_report(
            findings=[
                finding("A", Status.FAIL, Severity.LOW),
                finding("B", Status.FAIL, Severity.CRITICAL),
            ]
        )
        assert compare(before, after).worst_new_severity == "Critical"


class TestSnapshot:
    def test_reads_a_stored_report_the_same_as_a_live_one(self):
        report = make_report(findings=[finding("A")], components=[component_with_vuln()])
        live = Snapshot.from_report(report)
        stored = Snapshot.from_dict(report.to_dict())
        assert live.findings == stored.findings
        assert live.vulnerabilities == stored.vulnerabilities


class TestSummarise:
    def test_counts_across_sites(self):
        diffs = [
            compare(make_report(url="https://a.nl/", findings=[]).to_dict(),
                    make_report(url="https://a.nl/", findings=[finding("A")])),
            compare(make_report(url="https://b.nl/", findings=[finding("B")]).to_dict(),
                    make_report(url="https://b.nl/", findings=[finding("B", Status.PASS)])),
            compare(None, make_report(url="https://c.nl/")),
        ]
        summary = summarise(diffs)
        assert summary["sites_scanned"] == 3
        assert summary["sites_changed"] == 2
        assert summary["new_findings"] == 1
        assert summary["resolved_findings"] == 1
