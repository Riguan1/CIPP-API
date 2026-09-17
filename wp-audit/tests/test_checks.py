"""The individual check groups: fingerprinting, headers, certificates and scoring.

These are the pure functions -- given this markup, these headers, this certificate, what does the
report say. The end-to-end behaviour is covered in test_scanner.py; this is where the edge cases
that are hard to stage against a live server live.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from wpaudit.checks.headers import check_headers, check_php_version
from wpaudit.checks.transport import CertificateInfo, certificate_findings
from wpaudit.fingerprint import extract_components, fingerprint
from wpaudit.models import Finding, Severity, Status
from wpaudit.probe import ProbeResponse
from wpaudit.scoring import score_findings, sort_findings
from wpaudit.versions import compare_versions, is_outdated, parse_version, version_in_range

WP_PAGE = """<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="https://api.w.org/" href="https://example.com/wp-json/" />
<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.4" />
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.4"></script>
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.2.1" />
<link rel="stylesheet" href="/wp-content/themes/storefront/style.css?ver=4.5.1" />
<link rel="stylesheet" href="/wp-content/themes/storefront-child/style.css?ver=1.0.0" />
</head><body>content</body></html>"""


def response_with(headers: dict[str, str], set_cookie: list[str] | None = None) -> ProbeResponse:
    return ProbeResponse(
        url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        headers=headers,
        set_cookie=set_cookie or [],
        ok=True,
    )


def by_id(findings, finding_id):
    return next((f for f in findings if f.id == finding_id), None)


class TestVersions:
    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("6.4.2", "6.4.3", -1),
            ("6.4.3", "6.4.2", 1),
            ("6.4.2", "6.4.2", 0),
            ("6.5", "6.4.9", 1),
            ("5.9", "6.0", -1),
            ("1.2.3.4", "1.2.3.5", -1),
            ("10.0", "9.9", 1),
        ],
    )
    def test_orders_versions(self, left, right, expected):
        assert compare_versions(left, right) == expected

    def test_treats_a_missing_component_as_zero(self):
        # The classic bug: 6.4 read as 6.4.-1 and reported as older than 6.4.0.
        assert compare_versions("6.4", "6.4.0") == 0

    def test_compares_numerically_not_lexically(self):
        # '1.10' sorts before '1.9' as text, which reports a current plugin as outdated.
        assert compare_versions("1.10.0", "1.9.0") == 1

    def test_ignores_a_prerelease_suffix(self):
        assert compare_versions("6.4-beta1", "6.4") == 0

    def test_reports_no_difference_for_an_unparseable_version(self):
        # Keeps a garbage version string from becoming a vulnerability match.
        assert compare_versions("trunk", "6.4") == 0
        assert parse_version("trunk") is None
        assert is_outdated(None, "6.4") is False

    def test_range_bounds(self):
        assert version_in_range("5.7.0", "*", True, "5.7.1", True) is True
        assert version_in_range("5.7.1", "*", True, "5.7.1", True) is True
        assert version_in_range("5.7.1", "*", True, "5.7.1", False) is False
        assert version_in_range("8.0.0", "8.0.0", True, "8.2.1", True) is True
        assert version_in_range("7.9.9", "8.0.0", True, "8.2.1", True) is False
        assert version_in_range("8.0.0", "8.0.0", False, "8.2.1", True) is False

    def test_an_unreadable_version_never_matches_a_range(self):
        assert version_in_range(None, "*", True, "*", True) is False
        assert version_in_range("", "*", True, "*", True) is False


class TestFingerprint:
    def test_identifies_wordpress(self):
        result = fingerprint(WP_PAGE, base_url="https://example.com/")
        assert result.is_wordpress
        assert result.version == "6.4.2"
        assert result.version_source == "generator meta tag"

    def test_does_not_claim_a_plain_page_is_wordpress(self):
        assert fingerprint("<html><body><h1>Hello</h1></body></html>").is_wordpress is False

    def test_identifies_wordpress_from_headers_when_markup_is_rewritten(self):
        # A cache or page builder can strip every marker out of the HTML; headers remain.
        result = fingerprint("<html><body>cached</body></html>", {"X-Pingback": "https://e.com/xmlrpc.php"})
        assert result.is_wordpress

    def test_falls_back_to_a_core_asset_version(self):
        html = '<link href="/wp-includes/css/dist/block-library/style.min.css?ver=6.3.1">'
        result = fingerprint(html)
        assert result.version == "6.3.1"
        assert result.version_source == "core asset version query string"

    def test_reports_no_version_when_the_site_publishes_none(self):
        result = fingerprint('<html><link href="/wp-content/themes/x/style.css"></html>')
        assert result.is_wordpress
        assert result.version is None

    def test_extracts_plugins_and_themes(self):
        result = fingerprint(WP_PAGE, base_url="https://example.com/")
        assert {c.slug for c in result.plugins} == {"contact-form-7", "woocommerce"}
        assert {c.slug for c in result.themes} == {"storefront", "storefront-child"}

    def test_collapses_repeated_references_to_one_component(self):
        plugins = extract_components(WP_PAGE, "plugins")
        assert len([p for p in plugins if p.slug == "contact-form-7"]) == 1

    def test_keeps_the_highest_version_a_component_serves(self):
        # A component cannot be older than the newest version it serves; taking the lowest would
        # report a vulnerability that was already patched.
        html = (
            '<link href="/wp-content/plugins/demo/a.css?ver=1.2.0">'
            '<script src="/wp-content/plugins/demo/b.js?ver=1.10.0"></script>'
        )
        assert extract_components(html, "plugins")[0].version == "1.10.0"

    def test_records_a_component_that_serves_no_version(self):
        # Asset optimisers strip ?ver=. The plugin is still installed and still worth listing.
        component = extract_components('<script src="/wp-content/plugins/x/app.js"></script>', "plugins")[0]
        assert component.slug == "x"
        assert component.version is None

    def test_handles_minified_markup_without_quotes(self):
        html = "<link rel=stylesheet href=/wp-content/plugins/elementor/frontend.min.css?ver=3.18.0>"
        component = extract_components(html, "plugins")[0]
        assert (component.slug, component.version) == ("elementor", "3.18.0")


class TestHeaders:
    HARDENED = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'",
        "Server": "nginx",
    }

    def test_a_hardened_response_has_no_failures(self):
        findings = check_headers(response_with(self.HARDENED), is_https=True)
        assert [f for f in findings if f.status is Status.FAIL] == []

    def test_a_bare_response_reports_the_missing_headers(self):
        findings = check_headers(response_with({}), is_https=True)
        assert by_id(findings, "WEB-HSTS-MISSING").status is Status.FAIL
        assert by_id(findings, "WEB-CLICKJACKING").status is Status.FAIL
        assert by_id(findings, "WEB-NOSNIFF").status is Status.FAIL
        # A CSP that breaks a customer's checkout is worse than no CSP: advice, not a bug.
        assert by_id(findings, "WEB-CSP-MISSING").status is Status.WARN

    def test_recognises_headers_whatever_case_they_arrive_in(self):
        lowercase = {key.lower(): value for key, value in self.HARDENED.items()}
        findings = check_headers(response_with(lowercase), is_https=True)
        assert [f for f in findings if f.status is Status.FAIL] == []

    def test_warns_about_a_short_hsts_max_age(self):
        findings = check_headers(response_with({"Strict-Transport-Security": "max-age=300"}), is_https=True)
        assert by_id(findings, "WEB-HSTS-SHORT").status is Status.WARN

    def test_accepts_csp_frame_ancestors_instead_of_x_frame_options(self):
        headers = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'"}
        findings = check_headers(response_with(headers), is_https=True)
        assert by_id(findings, "WEB-CLICKJACKING").status is Status.PASS

    def test_skips_hsts_on_a_plain_http_page(self):
        # HSTS is ignored by browsers over HTTP; the missing transport is the finding.
        findings = check_headers(response_with({}), is_https=False)
        assert by_id(findings, "WEB-HSTS-MISSING") is None

    def test_reports_a_version_banner(self):
        findings = check_headers(response_with({"Server": "Apache/2.4.41 (Ubuntu)"}), is_https=True)
        assert by_id(findings, "WEB-BANNER-SERVER").status is Status.FAIL

    def test_accepts_a_server_header_with_no_version(self):
        findings = check_headers(response_with({"Server": "nginx"}), is_https=True)
        assert by_id(findings, "WEB-BANNER-SERVER") is None

    def test_reports_cookies_without_secure(self):
        findings = check_headers(
            response_with({}, ["wordpress_logged_in_abc=v; path=/; HttpOnly"]), is_https=True
        )
        assert by_id(findings, "WEB-COOKIE-SECURE").status is Status.FAIL

    def test_does_not_judge_cookie_flags_over_plain_http(self):
        findings = check_headers(response_with({}, ["a=1; path=/"]), is_https=False)
        assert by_id(findings, "WEB-COOKIE-SECURE") is None

    def test_gives_every_actionable_finding_a_recommendation(self):
        findings = check_headers(response_with({}), is_https=True)
        for finding in findings:
            if finding.status in (Status.FAIL, Status.WARN):
                assert finding.recommendation, f"{finding.id} asks someone to do something"


class TestPhpVersion:
    def test_reports_an_unsupported_branch(self):
        finding = check_php_version(None, "PHP/7.4.33")
        assert finding.status is Status.FAIL
        assert finding.severity is Severity.HIGH

    def test_reads_the_version_from_a_server_header_too(self):
        assert check_php_version("Apache/2.4.41 (Unix) PHP/5.6.40", None).status is Status.FAIL

    def test_returns_nothing_when_no_version_is_disclosed(self):
        assert check_php_version("nginx", None) is None

    def test_judges_against_the_date_rather_than_a_frozen_verdict(self):
        # The table holds end-of-support dates, so a branch supported today stops passing on its
        # own once that date goes by - nobody has to remember to edit the check.
        before = datetime(2025, 1, 1, tzinfo=timezone.utc)
        after = datetime(2026, 6, 1, tzinfo=timezone.utc)
        assert check_php_version(None, "PHP/8.1.2", now=before).status is Status.PASS
        assert check_php_version(None, "PHP/8.1.2", now=after).status is Status.FAIL

    def test_warns_when_end_of_support_is_close(self):
        near = datetime(2026, 11, 1, tzinfo=timezone.utc)  # PHP 8.2 ends 2026-12-31
        assert check_php_version(None, "PHP/8.2.1", now=near).status is Status.WARN


class TestCertificateFindings:
    def valid_cert(self, **overrides) -> CertificateInfo:
        defaults = dict(
            host="example.com",
            ok=True,
            trusted=True,
            subject="CN=example.com",
            issuer="CN=Test CA",
            not_before=datetime.now(timezone.utc) - timedelta(days=30),
            not_after=datetime.now(timezone.utc) + timedelta(days=60),
            days_remaining=60,
            protocol="TLSv1.3",
            key_type="RSA",
            key_size=2048,
        )
        defaults.update(overrides)
        return CertificateInfo(**defaults)

    def test_a_healthy_certificate_passes(self):
        findings = certificate_findings(self.valid_cert())
        assert [f for f in findings if f.status is Status.FAIL] == []

    def test_reports_an_expired_certificate_as_critical(self):
        cert = self.valid_cert(
            not_after=datetime.now(timezone.utc) - timedelta(days=5), days_remaining=-5
        )
        finding = by_id(certificate_findings(cert), "WEB-TLS-EXPIRED")
        assert finding.status is Status.FAIL
        assert finding.severity is Severity.CRITICAL

    def test_warns_before_expiry(self):
        cert = self.valid_cert(
            not_after=datetime.now(timezone.utc) + timedelta(days=10), days_remaining=10
        )
        assert by_id(certificate_findings(cert), "WEB-TLS-EXPIRING").status is Status.WARN

    def test_names_a_hostname_mismatch_specifically(self):
        cert = self.valid_cert(trusted=False, validation_error="Hostname mismatch, certificate is not valid")
        assert "hostname" in by_id(certificate_findings(cert), "WEB-TLS-VALIDATION").title

    def test_names_a_self_signed_certificate_specifically(self):
        cert = self.valid_cert(
            trusted=False, self_signed=True, validation_error="self signed certificate"
        )
        assert "self-signed" in by_id(certificate_findings(cert), "WEB-TLS-VALIDATION").title

    def test_reports_an_obsolete_protocol(self):
        cert = self.valid_cert(protocol="TLSv1")
        assert by_id(certificate_findings(cert), "WEB-TLS-PROTOCOL").status is Status.FAIL

    def test_does_not_overclaim_what_a_good_handshake_proves(self):
        # Negotiating TLS 1.3 says nothing about whether TLS 1.0 is still accepted.
        finding = by_id(certificate_findings(self.valid_cert()), "WEB-TLS-PROTOCOL")
        assert "does not prove" in finding.evidence

    def test_reports_a_small_rsa_key(self):
        cert = self.valid_cert(key_size=1024)
        assert by_id(certificate_findings(cert), "WEB-TLS-KEYSIZE").status is Status.FAIL

    def test_does_not_flag_an_ecdsa_key_for_its_size(self):
        # A 256-bit ECDSA key is stronger than a 2048-bit RSA one; comparing the numbers is wrong.
        cert = self.valid_cert(key_type="ECDSA", key_size=256)
        assert by_id(certificate_findings(cert), "WEB-TLS-KEYSIZE") is None

    def test_says_unknown_when_the_handshake_could_not_be_made(self):
        cert = CertificateInfo(host="example.com", ok=False, error="Timed out")
        assert by_id(certificate_findings(cert), "WEB-TLS-CERT").status is Status.UNKNOWN


class TestScoring:
    def finding(self, severity: Severity, status: Status, id_: str = "X") -> Finding:
        return Finding(id=id_, category="Test", title="t", severity=severity, status=status)

    def test_a_clean_scan_scores_full_marks(self):
        result = score_findings([self.finding(Severity.HIGH, Status.PASS)])
        assert (result.score, result.grade) == (100, "A")

    def test_an_unchecked_item_costs_nothing(self):
        # The scan admits it did not look; guessing in either direction would be worse.
        result = score_findings([self.finding(Severity.CRITICAL, Status.UNKNOWN)])
        assert result.score == 100

    def test_a_warning_costs_half_of_a_failure(self):
        failed = score_findings([self.finding(Severity.MEDIUM, Status.FAIL)])
        warned = score_findings([self.finding(Severity.MEDIUM, Status.WARN)])
        assert (100 - warned.score) == (100 - failed.score) / 2

    def test_one_critical_outranks_a_pile_of_small_issues(self):
        # The property that makes the grade mean anything to the person reading it.
        small = [self.finding(Severity.LOW, Status.FAIL, f"L{i}") for i in range(12)]
        critical = [self.finding(Severity.CRITICAL, Status.FAIL)]
        assert score_findings(critical).score < score_findings(small).score

    def test_never_goes_below_zero(self):
        many = [self.finding(Severity.CRITICAL, Status.FAIL, f"C{i}") for i in range(10)]
        result = score_findings(many)
        assert (result.score, result.grade) == (0, "F")

    def test_counts_findings_for_the_summary(self):
        result = score_findings(
            [
                self.finding(Severity.CRITICAL, Status.FAIL, "a"),
                self.finding(Severity.HIGH, Status.FAIL, "b"),
                self.finding(Severity.HIGH, Status.WARN, "c"),
                self.finding(Severity.LOW, Status.PASS, "d"),
                self.finding(Severity.LOW, Status.UNKNOWN, "e"),
            ]
        )
        assert result.summary["critical"] == 1
        assert result.summary["high"] == 2
        assert result.summary["passed"] == 1
        assert result.summary["unknown"] == 1

    @pytest.mark.parametrize(
        "severities,score,grade",
        [
            ([], 100, "A"),
            ([Severity.LOW] * 4, 88, "B"),
            ([Severity.HIGH, Severity.MEDIUM, Severity.LOW], 71, "C"),
            ([Severity.CRITICAL], 60, "D"),
            ([Severity.CRITICAL, Severity.CRITICAL], 20, "F"),
        ],
    )
    def test_grade_boundaries(self, severities, score, grade):
        findings = [self.finding(s, Status.FAIL, f"F{i}") for i, s in enumerate(severities)]
        result = score_findings(findings)
        assert (result.score, result.grade) == (score, grade)

    def test_sorts_what_needs_doing_first(self):
        findings = [
            self.finding(Severity.LOW, Status.PASS, "pass"),
            self.finding(Severity.MEDIUM, Status.FAIL, "medium-fail"),
            self.finding(Severity.CRITICAL, Status.FAIL, "critical-fail"),
            self.finding(Severity.HIGH, Status.WARN, "high-warn"),
        ]
        assert [f.id for f in sort_findings(findings)] == [
            "critical-fail",
            "medium-fail",
            "high-warn",
            "pass",
        ]
