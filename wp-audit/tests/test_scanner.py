"""The scan end to end, against a real HTTP server.

No mocks here: a fake WordPress site is started in-process with real sockets, planted with the
problems a neglected site has, and the scanner is pointed at it. That covers the parts that only
appear once the pieces are wired together -- the guard running before any request, a redirect
deciding which host is judged, vulnerability matching running against the inventory the
fingerprint produced, and one part failing without taking the scan with it.
"""

from __future__ import annotations

import pytest
from conftest import WP_HOME, Route

from wpaudit.checks.components import WordPressOrg
from wpaudit.models import Status
from wpaudit.scanner import scan


@pytest.fixture
def offline_org():
    """WordPress.org lookups switched off: these tests are about the scanner, not the network."""
    return WordPressOrg(enabled=False)


def find(report, finding_id):
    return next((f for f in report.findings if f.id == finding_id), None)


class TestGuard:
    def test_refuses_a_private_address(self):
        report = scan("http://192.168.1.10/")
        assert report.completed is False
        assert "public internet" in report.error

    def test_refuses_the_metadata_endpoint_before_any_request(self):
        report = scan("http://169.254.169.254/latest/meta-data/")
        assert report.completed is False
        assert report.requests_made == 0


class TestVulnerableSite:
    @pytest.fixture
    def report(self, make_site, allow_local_targets, vulndb, offline_org):
        site = make_site(
            {
                "/": Route(200, WP_HOME),
                "/wp-config.php.bak": Route(
                    200,
                    "<?php\ndefine('DB_NAME', 'wp_live');\ndefine('DB_PASSWORD', 'hunter2');",
                    content_type="text/plain",
                ),
                "/wp-content/debug.log": Route(
                    200, "PHP Warning:  include() failed in /var/www/x.php on line 12",
                    content_type="text/plain",
                ),
                "/wp-content/uploads/": Route(
                    200, "<html><head><title>Index of /wp-content/uploads</title></head><body></body></html>"
                ),
                "/xmlrpc.php": Route(
                    405, "XML-RPC server accepts POST requests only.", content_type="text/plain"
                ),
                "/wp-json/wp/v2/users": Route(
                    200,
                    '[{"id":1,"name":"Admin","slug":"administrator"}]',
                    content_type="application/json",
                ),
                "/wp-login.php": Route(
                    200, '<form name="loginform"><input name="user_login"><input id="wp-submit"></form>'
                ),
            },
            default_headers=[("X-Powered-By", "PHP/7.4.33"), ("Server", "Apache/2.4.41 (Ubuntu)")],
        )
        return scan(site.base_url, database=vulndb, wordpress_org=offline_org, max_requests=40)

    def test_completes_and_detects_wordpress(self, report):
        assert report.completed
        assert report.is_wordpress
        assert report.wordpress_version == "6.3.1"

    def test_finds_the_exposed_config_backup(self, report):
        finding = find(report, "WP-CONFIG-BACKUP")
        assert finding.status is Status.FAIL
        assert "rotate" in finding.recommendation

    def test_finds_the_debug_log_and_directory_listing(self, report):
        assert find(report, "WP-DEBUG-LOG").status is Status.FAIL
        assert find(report, "WP-DIRECTORY-LISTING").status is Status.FAIL

    def test_finds_xmlrpc_and_user_enumeration(self, report):
        assert find(report, "WP-XMLRPC").status is Status.FAIL
        finding = find(report, "WP-REST-USERS")
        assert finding.status is Status.FAIL
        assert "administrator" in finding.evidence

    def test_reports_the_unsupported_php_branch(self, report):
        assert find(report, "WEB-PHP-EOL").status is Status.FAIL

    def test_matches_known_vulnerabilities_against_the_detected_versions(self, report):
        core = find(report, "VULN-CORE")
        assert core.status is Status.FAIL
        assert "CVE-2023-39999" in core.evidence

        plugin = find(report, "VULN-PLUGIN-CONTACT-FORM-7")
        assert plugin.status is Status.FAIL
        assert "CVE-2023-6449" in plugin.evidence
        assert "5.7.2" in plugin.recommendation

    def test_attaches_the_matches_to_the_component_inventory(self, report):
        plugin = next(c for c in report.components if c.slug == "contact-form-7")
        assert [v.cve for v in plugin.vulnerabilities] == ["CVE-2023-6449"]

    def test_does_not_flag_a_component_outside_the_affected_range(self, report):
        # WooCommerce 8.2.1 is the last affected version in the fixture, so it matches; the theme
        # at 1.1 is past its advisory and must not.
        theme = next(c for c in report.components if c.slug == "twentytwentythree")
        assert theme.vulnerabilities == []

    def test_grades_the_site_badly(self, report):
        assert report.grade in ("D", "F")
        assert report.summary["critical"] >= 1

    def test_stays_within_its_request_budget(self, report):
        assert report.requests_made <= 40

    def test_only_issues_read_only_requests(self, make_site, allow_local_targets, vulndb, offline_org):
        site = make_site({"/": Route(200, WP_HOME)})
        scan(site.base_url, database=vulndb, wordpress_org=offline_org)
        assert set(site.methods) <= {"GET", "HEAD"}


class TestHealthySite:
    def test_reports_no_vulnerabilities_without_claiming_safety(
        self, make_site, allow_local_targets, vulndb, offline_org
    ):
        # Every version moved past its advisory in the fixture feed: core, the plugin whose range
        # ends at 5.7.1, and WooCommerce, whose range ends at the 8.2.1 the default page serves.
        clean_home = (
            WP_HOME.replace("6.3.1", "6.4.2").replace("5.7.0", "5.9.0").replace("8.2.1", "8.3.0")
        )
        site = make_site({"/": Route(200, clean_home)})
        report = scan(site.base_url, database=vulndb, wordpress_org=offline_org)

        finding = find(report, "VULN-NONE-MATCHED")
        assert finding.status is Status.PASS
        # The wording has to stop an MSP telling a customer the site is safe.
        assert "not a guarantee" in finding.recommendation


class TestDegrading:
    def test_reports_an_unreachable_site_rather_than_raising(self, allow_local_targets):
        # Nothing is listening on this port.
        report = scan("http://127.0.0.1:9/", max_requests=5)
        assert report.completed is False
        assert report.error

    def test_says_so_when_there_is_no_vulnerability_database(
        self, make_site, allow_local_targets, offline_org, tmp_path
    ):
        from wpaudit.vulndb.store import VulnerabilityDatabase

        site = make_site({"/": Route(200, WP_HOME)})
        empty = VulnerabilityDatabase(tmp_path / "empty.sqlite")
        report = scan(site.base_url, database=empty, wordpress_org=offline_org)

        finding = find(report, "VULN-DB-MISSING")
        assert finding.status is Status.UNKNOWN
        assert "wp-audit update" in finding.recommendation
        empty.close()

    def test_flags_components_it_could_not_version_match(
        self, make_site, allow_local_targets, vulndb, offline_org
    ):
        # An asset optimiser that strips ?ver= leaves a plugin that no feed can be matched against.
        stripped = '<html><head><link href="/wp-content/plugins/some-plugin/a.css">' \
                   '<meta name="generator" content="WordPress 6.4.2"></head><body>x</body></html>'
        site = make_site({"/": Route(200, stripped)})
        report = scan(site.base_url, database=vulndb, wordpress_org=offline_org)

        finding = find(report, "VULN-VERSION-UNKNOWN")
        assert finding.status is Status.UNKNOWN
        assert "some-plugin" in finding.evidence

    def test_confirm_components_recovers_a_version_from_readme(
        self, make_site, allow_local_targets, vulndb, offline_org
    ):
        stripped = '<html><head><link href="/wp-content/plugins/contact-form-7/a.css">' \
                   '<meta name="generator" content="WordPress 6.4.2"></head><body>x</body></html>'
        site = make_site(
            {
                "/": Route(200, stripped),
                "/wp-content/plugins/contact-form-7/readme.txt": Route(
                    200,
                    "=== Contact Form 7 ===\nContributors: takayukister\nStable tag: 5.7.0\n",
                    content_type="text/plain",
                ),
            }
        )
        report = scan(
            site.base_url,
            database=vulndb,
            wordpress_org=offline_org,
            confirm_components=True,
            max_requests=40,
        )

        plugin = next(c for c in report.components if c.slug == "contact-form-7")
        assert plugin.version == "5.7.0"
        # And the version it recovered is what makes the vulnerability visible at all.
        assert find(report, "VULN-PLUGIN-CONTACT-FORM-7").status is Status.FAIL


class TestNonWordPressSite:
    def test_says_so_and_still_reports_on_headers(
        self, make_site, allow_local_targets, vulndb, offline_org
    ):
        site = make_site({"/": Route(200, "<html><body><h1>A static site</h1></body></html>")})
        report = scan(site.base_url, database=vulndb, wordpress_org=offline_org)

        assert report.is_wordpress is False
        assert find(report, "WP-NOT-DETECTED").status is Status.INFO
        assert find(report, "WEB-NOSNIFF") is not None
        assert find(report, "WP-XMLRPC") is None


class TestSoft404Site:
    def test_does_not_report_a_themed_404_as_an_exposed_config(
        self, make_site, allow_local_targets, vulndb, offline_org
    ):
        # The whole point of the content signatures: status 200 proves nothing on these sites.
        site = make_site({"/": Route(200, WP_HOME)}, soft_404=True)
        report = scan(site.base_url, database=vulndb, wordpress_org=offline_org, max_requests=40)

        assert find(report, "WP-CONFIG-BACKUP") is None
        assert find(report, "WP-SOFT-404").status is Status.INFO


class TestContentChecks:
    def test_reports_php_errors_printed_on_the_page(
        self, make_site, allow_local_targets, vulndb, offline_org
    ):
        # Exactly what PHP emits with html_errors on, tags and all.
        error = (
            "<br />\n<b>Warning</b>:  include(): Failed opening 'parts/header.php' for inclusion "
            "in <b>/var/www/html/wp-content/themes/acme/index.php</b> on line <b>42</b><br />"
        )
        site = make_site({"/": Route(200, WP_HOME + error)})
        report = scan(site.base_url, database=vulndb, wordpress_org=offline_org)
        assert find(report, "WP-PHP-ERRORS").status is Status.FAIL

    def test_does_not_read_ordinary_prose_as_a_php_error(
        self, make_site, allow_local_targets, vulndb, offline_org
    ):
        prose = "<p>Warning: our office is closed. Read the notice on line two of the letter.</p>"
        site = make_site({"/": Route(200, WP_HOME + prose)})
        report = scan(site.base_url, database=vulndb, wordpress_org=offline_org)
        assert find(report, "WP-PHP-ERRORS") is None
