"""The single request everything else is built on, against a real server.

The cases here are the ones that are invisible until they bite: a redirect chain that leaves the
public internet, repeated Set-Cookie headers that a naive reader turns into cookies that do not
exist, and a body big enough to matter.
"""

from __future__ import annotations

from conftest import Route

from wpaudit.probe import Prober


class TestBasics:
    def test_reads_a_page(self, make_site, allow_local_targets):
        site = make_site({"/": Route(200, "<html>hello</html>")})
        with Prober() as prober:
            response = prober.get(site.base_url)
        assert response.ok
        assert response.status_code == 200
        assert "hello" in response.text

    def test_treats_a_404_as_an_answer_not_a_failure(self, make_site, allow_local_targets):
        # Most of what a scan asks for does not exist.
        site = make_site({})
        with Prober() as prober:
            response = prober.get(site.base_url + "missing")
        assert response.ok
        assert response.status_code == 404

    def test_returns_a_refused_connection_instead_of_raising(self, allow_local_targets):
        with Prober(timeout=2) as prober:
            response = prober.get("http://127.0.0.1:9/")
        assert response.ok is False
        assert response.error

    def test_header_lookup_ignores_case(self, make_site, allow_local_targets):
        # RFC 9110: field names are case-insensitive, and real servers use every spelling.
        site = make_site({"/": Route(200, "x", headers=[("X-Frame-Options", "DENY")])})
        with Prober() as prober:
            response = prober.get(site.base_url)
        assert response.header("x-frame-options") == "DENY"

    def test_refuses_a_method_that_is_not_read_only(self, allow_local_targets):
        with Prober() as prober:
            try:
                prober.get("http://example.com/", method="POST")
            except ValueError as exc:
                assert "read-only" in str(exc)
            else:  # pragma: no cover
                raise AssertionError("POST should be refused")


class TestCookies:
    def test_keeps_repeated_set_cookie_headers_apart(self, make_site, allow_local_targets):
        # An Expires attribute contains a comma, so reading the comma-joined header would invent
        # cookies and then report them as insecure.
        site = make_site(
            {
                "/": Route(
                    200,
                    "x",
                    headers=[
                        ("Set-Cookie", "a=1; expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure"),
                        ("Set-Cookie", "b=2; Path=/"),
                    ],
                )
            }
        )
        with Prober() as prober:
            response = prober.get(site.base_url)
        assert len(response.set_cookie) == 2
        assert response.set_cookie[0].startswith("a=1")
        assert response.set_cookie[1].startswith("b=2")

    def test_does_not_carry_cookies_between_requests(self, make_site, allow_local_targets):
        # A scanner that starts holding a session cookie stops seeing the anonymous view.
        site = make_site({"/": Route(200, "x", headers=[("Set-Cookie", "session=abc; Path=/")])})
        with Prober() as prober:
            prober.get(site.base_url)
            prober.get(site.base_url)
        assert len(prober.session.cookies) == 0


class TestRedirects:
    def test_follows_a_redirect_and_records_where_it_landed(self, make_site, allow_local_targets):
        site = make_site(
            {
                "/start": Route(301, "", headers=[("Location", "/end")]),
                "/end": Route(200, "arrived"),
            }
        )
        with Prober() as prober:
            response = prober.get(site.base_url + "start")
        assert response.ok
        assert response.text == "arrived"
        assert response.final_url.endswith("/end")
        assert response.redirected is True

    def test_counts_every_hop_against_the_budget(self, make_site, allow_local_targets):
        site = make_site(
            {
                "/a": Route(302, "", headers=[("Location", "/b")]),
                "/b": Route(302, "", headers=[("Location", "/c")]),
                "/c": Route(200, "done"),
            }
        )
        with Prober() as prober:
            prober.get(site.base_url + "a")
        assert prober.requests_made == 3

    def test_stops_after_too_many_redirects(self, make_site, allow_local_targets):
        site = make_site({"/loop": Route(302, "", headers=[("Location", "/loop")])})
        with Prober(max_redirects=2) as prober:
            response = prober.get(site.base_url + "loop")
        assert response.ok is False
        assert "redirect" in response.error.lower()

    def test_refuses_a_redirect_into_private_space(self, make_site):
        # The guard that cleared the original hostname says nothing about where a redirect went.
        # Without re-checking each hop, an open redirect is enough to reach the metadata API.
        site = make_site(
            {
                "/": Route(
                    302, "", headers=[("Location", "http://169.254.169.254/latest/meta-data/")]
                )
            }
        )
        with Prober() as prober:
            # No allow_local_targets here: the real guard is in play, and it lets the first
            # loopback request through only because the test server IS the first request.
            response = prober.get(site.base_url)
        assert response.ok is False
        assert "cannot be scanned" in response.error


class TestBudget:
    def test_refuses_to_exceed_the_request_ceiling(self, make_site, allow_local_targets):
        site = make_site({"/": Route(200, "x")})
        with Prober(max_requests=2) as prober:
            prober.get(site.base_url)
            prober.get(site.base_url)
            third = prober.get(site.base_url)
        assert prober.requests_made == 2
        assert third.ok is False
        assert "budget" in third.error.lower()


class TestLargeBodies:
    def test_truncates_a_body_past_the_limit(self, make_site, allow_local_targets, monkeypatch):
        monkeypatch.setattr("wpaudit.probe.MAX_CONTENT_BYTES", 1024)
        site = make_site({"/": Route(200, "x" * 20000)})
        with Prober() as prober:
            response = prober.get(site.base_url)
        assert response.truncated is True
        assert response.content_length <= 1024 + 8192  # the chunk that crossed the limit
