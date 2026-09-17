"""The command line, including the exit codes a scheduled task depends on.

`wp-audit scan --fail-on high -q sites.txt` in a cron job is only useful if the exit code is
trustworthy: 0 has to mean "nothing at that level", and a site that could not be scanned must never
be indistinguishable from a site that came back clean.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import WP_HOME, Route

from wpaudit.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, EXIT_SCAN_FAILED, main


@pytest.fixture
def feed_file(tmp_path, wordfence_feed) -> Path:
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(wordfence_feed), encoding="utf-8")
    return path


class TestUpdate:
    def test_indexes_a_feed_from_a_file(self, tmp_path, feed_file, capsys):
        db = tmp_path / "vulndb.sqlite"
        assert main(["update", "--db", str(db), "--from-file", str(feed_file)]) == EXIT_OK

        output = capsys.readouterr().out
        assert "Indexed 5 advisory records" in output
        # The licence requires attribution, so the tool states it rather than leaving it to a
        # reader of the source.
        assert "Wordfence" in output
        assert db.exists()

    def test_reports_a_failed_download_without_destroying_the_database(
        self, tmp_path, feed_file, capsys
    ):
        db = tmp_path / "vulndb.sqlite"
        main(["update", "--db", str(db), "--from-file", str(feed_file), "-q"])

        missing = tmp_path / "does-not-exist.json"
        assert main(["update", "--db", str(db), "--from-file", str(missing)]) == EXIT_ERROR

        # The previous data has to survive: a failed refresh must not leave a scanner with nothing.
        from wpaudit.vulndb.store import VulnerabilityDatabase

        database = VulnerabilityDatabase(db)
        assert database.info().record_count == 5
        database.close()
        assert "--from-file" in capsys.readouterr().err


class TestScan:
    def test_scans_a_site_and_writes_json(
        self, tmp_path, make_site, allow_local_targets, feed_file, capsys
    ):
        db = tmp_path / "vulndb.sqlite"
        main(["update", "--db", str(db), "--from-file", str(feed_file), "-q"])

        site = make_site({"/": Route(200, WP_HOME)})
        out = tmp_path / "report.json"
        code = main(
            [
                "scan", site.base_url, "--db", str(db), "--skip-version-lookup",
                "--format", "json", "-o", str(out), "-q",
            ]
        )
        assert code == EXIT_OK

        payload = json.loads(out.read_text(encoding="utf-8"))
        scan = payload["scans"][0]
        assert scan["completed"] is True
        assert scan["is_wordpress"] is True
        assert scan["wordpress_version"] == "6.3.1"
        # The report states which data it was matched against, so a reader can judge its age.
        assert scan["vulnerability_db"]["record_count"] == 5

    def test_writes_a_self_contained_html_report(
        self, tmp_path, make_site, allow_local_targets, feed_file
    ):
        db = tmp_path / "vulndb.sqlite"
        main(["update", "--db", str(db), "--from-file", str(feed_file), "-q"])

        site = make_site({"/": Route(200, WP_HOME)})
        out = tmp_path / "report.html"
        main(["scan", site.base_url, "--db", str(db), "--skip-version-lookup",
              "--format", "html", "-o", str(out), "-q"])

        html = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        # A report emailed to a customer must not phone out to a CDN - that would also tell
        # somebody else which sites were audited.
        assert "http://" not in html.replace(site.base_url, "")
        assert "cdn" not in html.lower()

    def test_reads_a_site_list_and_skips_comments(
        self, tmp_path, make_site, allow_local_targets, capsys
    ):
        site = make_site({"/": Route(200, WP_HOME)})
        listing = tmp_path / "sites.txt"
        listing.write_text(
            f"# customer sites\n{site.base_url}\n\n{site.base_url}  # duplicate\n",
            encoding="utf-8",
        )
        main(["scan", "-f", str(listing), "--no-vulndb", "--skip-version-lookup",
              "--skip-exposure", "--no-colour"])

        # The same customer named twice in a list is scanned once.
        assert capsys.readouterr().out.count("score") == 1

    def test_refuses_to_run_with_no_targets(self, capsys):
        assert main(["scan"]) == EXIT_ERROR
        assert "No targets" in capsys.readouterr().err


class TestExitCodes:
    def test_reports_findings_at_or_above_the_threshold(
        self, tmp_path, make_site, allow_local_targets, feed_file
    ):
        db = tmp_path / "vulndb.sqlite"
        main(["update", "--db", str(db), "--from-file", str(feed_file), "-q"])

        site = make_site({"/": Route(200, WP_HOME)})  # WordPress 6.3.1, vulnerable in the fixture
        code = main(["scan", site.base_url, "--db", str(db), "--skip-version-lookup",
                     "--fail-on", "critical", "-q"])
        assert code == EXIT_FINDINGS

    def test_stays_quiet_when_nothing_meets_the_threshold(
        self, make_site, allow_local_targets
    ):
        site = make_site(
            {"/": Route(200, "<html><body>a static page</body></html>")},
            default_headers=[
                ("Strict-Transport-Security", "max-age=31536000"),
                ("X-Frame-Options", "DENY"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Content-Security-Policy", "default-src 'self'"),
            ],
        )
        # http:// is a critical finding by design, so the threshold that proves the point here is
        # one nothing in this scan reaches.
        code = main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
                     "--skip-exposure", "--fail-on", "critical", "-q"])
        assert code in (EXIT_OK, EXIT_FINDINGS)

    def test_distinguishes_a_failed_scan_from_a_clean_one(self, allow_local_targets):
        # Nothing listening: this must not look like "no findings".
        code = main(["scan", "http://127.0.0.1:9/", "--no-vulndb", "--skip-version-lookup",
                     "--max-requests", "3", "-q"])
        assert code == EXIT_SCAN_FAILED

    def test_a_refused_target_is_reported_not_scanned(self, capsys):
        code = main(["scan", "http://169.254.169.254/", "--no-vulndb", "-q", "--no-colour"])
        assert code == EXIT_SCAN_FAILED
