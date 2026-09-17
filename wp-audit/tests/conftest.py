"""Shared fixtures.

The important one is `fake_site`: a real HTTP server, in-process, serving whatever a test wants it
to. Most of this scanner's failure modes live in the gap between "what the code expects a server to
send" and "what servers actually send" -- repeated Set-Cookie headers, soft 404s, redirect chains,
bodies without a Content-Length -- and mocks reproduce the expectation rather than the reality. A
real socket does not.
"""

from __future__ import annotations

import http.server
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from wpaudit.target import TargetResult

WP_HOME = """<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 6.3.1" />
<link rel="https://api.w.org/" href="/wp-json/" />
<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.3.1" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.7.0" />
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.7.0"></script>
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.2.1" />
<link rel="stylesheet" href="/wp-content/themes/twentytwentythree/style.css?ver=1.1" />
</head><body>Welcome to the site</body></html>"""


@dataclass
class Route:
    status: int = 200
    body: str = ""
    content_type: str = "text/html; charset=UTF-8"
    headers: list[tuple[str, str]] = field(default_factory=list)


class FakeSite:
    """A tiny configurable web server. `routes` maps a path to a Route."""

    def __init__(self, routes: dict[str, Route], *, soft_404: bool = False,
                 default_headers: list[tuple[str, str]] | None = None) -> None:
        self.routes = routes
        self.soft_404 = soft_404
        self.default_headers = default_headers or []
        self.requests: list[str] = []
        self.methods: list[str] = []

        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # keep pytest output readable
                pass

            def _respond(self, write_body: bool):
                site.requests.append(self.path)
                site.methods.append(self.command)
                route = site.routes.get(self.path)
                if route is None:
                    if site.soft_404:
                        route = Route(200, "<html><body>Oops, that page cannot be found.</body></html>")
                    else:
                        route = Route(404, "<html><body>Not Found</body></html>")

                body = route.body.encode("utf-8")
                self.send_response(route.status)
                self.send_header("Content-Type", route.content_type)
                self.send_header("Content-Length", str(len(body)))
                for key, value in site.default_headers:
                    self.send_header(key, value)
                for key, value in route.headers:
                    self.send_header(key, value)
                self.end_headers()
                if write_body:
                    self.wfile.write(body)

            def do_GET(self):
                self._respond(True)

            def do_HEAD(self):
                self._respond(False)

        class QuietServer(http.server.ThreadingHTTPServer):
            # The scanner closes a connection as soon as it has read enough, which is the correct
            # behaviour for a truncating client and which the stdlib server reports as an
            # unhandled ConnectionResetError all over the test output.
            def handle_error(self, request, client_address):
                pass

        self._server = QuietServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> FakeSite:
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"


@pytest.fixture(autouse=True)
def isolate_user_state(tmp_path, monkeypatch):
    """Keep every test out of the real ~/.cache/wp-audit.

    The scan history and vulnerability database default to the user's cache directory, which the
    CLI tests would otherwise write to for real - polluting whatever the developer has scanned, and
    making the tests depend on it. Autouse so no new test can forget.
    """
    monkeypatch.setenv("WP_AUDIT_HISTORY", str(tmp_path / "history.sqlite"))
    monkeypatch.setenv("WP_AUDIT_DB", str(tmp_path / "vulndb.sqlite"))
    # And a real Wordfence token, so a developer who has one configured sees what CI sees.
    monkeypatch.delenv("WORDFENCE_API_TOKEN", raising=False)


@pytest.fixture
def make_site():
    """Start a fake site for the duration of one test."""
    sites: list[FakeSite] = []

    def factory(routes: dict[str, Route] | None = None, **kwargs) -> FakeSite:
        site = FakeSite(routes or {}, **kwargs)
        site.__enter__()
        sites.append(site)
        return site

    yield factory

    for site in sites:
        site.__exit__(None, None, None)


@pytest.fixture
def allow_local_targets(monkeypatch):
    """Let the scanner reach the in-process test server.

    The guard refuses loopback and non-default ports, which is exactly what it is for and exactly
    what a local test server is. Rather than adding a production flag that switches the guard off
    -- the kind of flag that eventually ships enabled -- the tests replace it here, and the guard
    itself is covered thoroughly by `test_target.py`.
    """

    def permissive(url: str, **kwargs) -> TargetResult:
        from urllib.parse import urlsplit

        parts = urlsplit(url if "://" in url else "https://" + url)
        return TargetResult(
            True,
            url=url if "://" in url else "https://" + url,
            host=parts.hostname or "",
            scheme=parts.scheme,
            addresses=[parts.hostname or ""],
        )

    monkeypatch.setattr("wpaudit.probe.validate_target", permissive)
    monkeypatch.setattr("wpaudit.scanner.validate_target", permissive)


@pytest.fixture
def wordfence_feed() -> dict:
    """A feed in the shape Wordfence Intelligence publishes."""
    path = Path(__file__).parent / "fixtures" / "wordfence_feed.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def vulndb(tmp_path, wordfence_feed):
    """A database preloaded with the sample feed."""
    from wpaudit.vulndb.sources import WordfenceSource
    from wpaudit.vulndb.store import VulnerabilityDatabase

    database = VulnerabilityDatabase(tmp_path / "vulndb.sqlite")
    source = WordfenceSource()
    database.replace_source(source.name, source.parse(wordfence_feed), attribution=source.attribution)
    yield database
    database.close()


@pytest.fixture
def wp_routes() -> dict[str, Route]:
    """A plain, healthy-looking WordPress site."""
    return {"/": Route(200, WP_HOME)}
