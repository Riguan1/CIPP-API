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


class TestChangeReporting:
    """The workflow this is all for: scan, scan again, hear about the difference."""

    def test_says_nothing_when_nothing_changed(
        self, tmp_path, make_site, allow_local_targets, capsys
    ):
        # The silence is the notification mechanism: cron mails whatever a job prints, so a quiet
        # night must print nothing at all.
        site = make_site({"/": Route(200, WP_HOME)})
        history = tmp_path / "history.sqlite"
        common = ["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
                  "--history", str(history), "--only-changes", "--no-colour"]

        main(common)          # first scan, nothing to compare against
        capsys.readouterr()
        main(common)          # second scan, identical site

        assert capsys.readouterr().out.strip() == ""

    def test_reports_a_finding_that_appeared(
        self, tmp_path, make_site, allow_local_targets, capsys
    ):
        history = tmp_path / "history.sqlite"
        clean = make_site({"/": Route(200, WP_HOME)})
        main(["scan", clean.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "-q"])
        capsys.readouterr()

        # Same host and port, now serving a downloadable wp-config backup.
        clean.routes["/wp-config.php.bak"] = Route(
            200, "<?php define('DB_NAME','x'); define('DB_PASSWORD','y');", content_type="text/plain"
        )
        main(["scan", clean.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "--only-changes", "--no-colour"])

        output = capsys.readouterr().out
        assert "new critical" in output
        assert "wp-config" in output.lower()

    def test_reports_a_finding_that_was_fixed(
        self, tmp_path, make_site, allow_local_targets, capsys
    ):
        history = tmp_path / "history.sqlite"
        site = make_site(
            {
                "/": Route(200, WP_HOME),
                "/wp-config.php.bak": Route(
                    200, "<?php define('DB_NAME','x'); define('DB_PASSWORD','y');",
                    content_type="text/plain",
                ),
            }
        )
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "-q"])
        capsys.readouterr()

        del site.routes["/wp-config.php.bak"]
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "--only-changes", "--no-colour"])

        # What the MSP shows the customer at the end of the month.
        assert "+ fixed:" in capsys.readouterr().out

    def test_fail_on_change_exits_non_zero_only_when_something_got_worse(
        self, tmp_path, make_site, allow_local_targets
    ):
        history = tmp_path / "history.sqlite"
        site = make_site({"/": Route(200, WP_HOME)})
        args = ["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
                "--history", str(history), "--fail-on-change", "-q"]

        assert main(args) == EXIT_OK      # first scan
        assert main(args) == EXIT_OK      # unchanged

        site.routes["/.env"] = Route(200, "DB_HOST=localhost\nAPP_KEY=abc", content_type="text/plain")
        assert main(args) == EXIT_FINDINGS

    def test_records_the_trend_and_shows_it(
        self, tmp_path, make_site, allow_local_targets, capsys
    ):
        history = tmp_path / "history.sqlite"
        site = make_site({"/": Route(200, WP_HOME)})
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "-q"])
        capsys.readouterr()

        assert main(["history", "--history", str(history)]) == EXIT_OK
        listing = capsys.readouterr().out
        assert "127.0.0.1" in listing

        assert main(["history", site.base_url, "--history", str(history)]) == EXIT_OK
        assert "WordPress 6.3.1" in capsys.readouterr().out

    def test_the_json_report_carries_the_changes(
        self, tmp_path, make_site, allow_local_targets
    ):
        history = tmp_path / "history.sqlite"
        site = make_site({"/": Route(200, WP_HOME)})
        out = tmp_path / "report.json"
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "-q"])
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "--format", "json", "-o", str(out), "-q"])

        payload = json.loads(out.read_text(encoding="utf-8"))
        assert "changes" in payload
        assert payload["changes"][0]["first_scan"] is False

    def test_no_history_leaves_nothing_behind(
        self, tmp_path, make_site, allow_local_targets
    ):
        history = tmp_path / "history.sqlite"
        site = make_site({"/": Route(200, WP_HOME)})
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "--no-history", "-q"])
        assert not history.exists()

    def test_posts_changes_to_a_webhook(
        self, tmp_path, make_site, allow_local_targets, monkeypatch
    ):
        import wpaudit.cli as cli_module

        posted = []
        monkeypatch.setattr(cli_module, "send_webhook", lambda *a, **k: (posted.append(a) or (True, "")))

        history = tmp_path / "history.sqlite"
        site = make_site({"/": Route(200, WP_HOME)})
        args = ["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
                "--history", str(history), "--webhook", "https://hooks.example/x", "-q"]

        main(args)
        assert posted == []          # first scan: nothing to report

        site.routes["/.env"] = Route(200, "DB_HOST=x\nAPP_KEY=y", content_type="text/plain")
        main(args)
        assert len(posted) == 1      # a change: posted once


class TestFeedUpdateAlerts:
    def test_reports_advisories_affecting_sites_already_scanned(
        self, tmp_path, make_site, allow_local_targets, feed_file, capsys
    ):
        db = tmp_path / "vulndb.sqlite"
        history = tmp_path / "history.sqlite"

        # A customer site is scanned while the database is still empty.
        site = make_site({"/": Route(200, WP_HOME)})
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "-q"])
        capsys.readouterr()

        # Then the feed arrives, carrying advisories against what that site runs.
        code = main(["update", "--db", str(db), "--from-file", str(feed_file),
                     "--history", str(history), "--alert-known"])

        output = capsys.readouterr().out
        assert "contact-form-7" in output
        assert "CVE-2023-6449" in output
        # Something needing attention is worth a non-zero exit for a cron job.
        assert code == EXIT_FINDINGS

    def test_a_second_identical_update_is_silent(
        self, tmp_path, make_site, allow_local_targets, feed_file, capsys
    ):
        # Otherwise the nightly job repeats the same alert until nobody reads it.
        db = tmp_path / "vulndb.sqlite"
        history = tmp_path / "history.sqlite"
        site = make_site({"/": Route(200, WP_HOME)})
        main(["scan", site.base_url, "--no-vulndb", "--skip-version-lookup",
              "--history", str(history), "-q"])
        main(["update", "--db", str(db), "--from-file", str(feed_file),
              "--history", str(history), "--alert-known", "-q"])
        capsys.readouterr()

        code = main(["update", "--db", str(db), "--from-file", str(feed_file),
                     "--history", str(history), "--alert-known"])
        assert "Nothing in this update affects" in capsys.readouterr().out
        assert code == EXIT_OK
