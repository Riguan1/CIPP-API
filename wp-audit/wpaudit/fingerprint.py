"""Working out whether a page is WordPress, which version, and what it loads.

Everything here reads markup and headers the site already published; no request is made from this
module. That keeps detection testable against captured pages and leaves the request budget in the
caller's hands.

The inventory this produces is what the vulnerability matching runs against, so its failure mode is
quiet: a plugin that is not detected is a plugin that is never checked, and the report looks
cleaner for it. Two things routinely hide components from any passive scanner -- an asset optimiser
that strips or rewrites the `?ver=` query string, and a site that moves `wp-content` elsewhere --
and both show up here as an empty or partial list rather than as a warning. `readme.txt`
confirmation (see `checks.exposure.confirm_components`) exists to claw some of that back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from .models import Component
from .versions import compare_versions

_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+(\d+(?:\.\d+){0,2})""",
    re.IGNORECASE,
)
_CORE_ASSET_VERSION = re.compile(
    r"/wp-includes/[^\"'\s>]*[?&]ver=(\d+(?:\.\d+){1,2})", re.IGNORECASE
)
_FEED_GENERATOR = re.compile(r"wordpress\.org/\?v=(\d+(?:\.\d+){0,2})", re.IGNORECASE)

_VERSION_SOURCES = (
    ("generator meta tag", _GENERATOR),
    ("core asset version query string", _CORE_ASSET_VERSION),
    ("feed generator link", _FEED_GENERATOR),
)

_SIGNALS = (
    (re.compile(r"/wp-content/", re.IGNORECASE), "wp-content asset paths"),
    (re.compile(r"/wp-includes/", re.IGNORECASE), "wp-includes asset paths"),
    (re.compile(r"api\.w\.org", re.IGNORECASE), "WordPress REST API link tag"),
    (re.compile(r"<meta[^>]+generator[^>]+WordPress", re.IGNORECASE), "generator meta tag"),
    (re.compile(r"wp-json", re.IGNORECASE), "wp-json endpoint reference"),
    (
        re.compile(r"wp-emoji-release\.min\.js|wp-block-library", re.IGNORECASE),
        "core script/style handles",
    ),
)

# Slugs are lowercase alphanumeric with dashes and underscores by WordPress.org convention.
_ASSET_PATH = r"/wp-content/{kind}/([A-Za-z0-9][A-Za-z0-9_\-]{{0,62}})/([^\"'\s>)]*)"
_ASSET_VERSION = re.compile(r"[?&]ver=(\d+(?:\.\d+){0,3})(?:[&\"']|$)")


@dataclass
class Fingerprint:
    is_wordpress: bool = False
    signals: list[str] = field(default_factory=list)
    version: str | None = None
    version_source: str | None = None
    plugins: list[Component] = field(default_factory=list)
    themes: list[Component] = field(default_factory=list)

    @property
    def components(self) -> list[Component]:
        return list(self.plugins) + list(self.themes)


def extract_components(html: str, kind: str, base_url: str | None = None) -> list[Component]:
    """Pull plugin or theme slugs, and their versions, out of a page.

    One slug appears many times on a real page -- a plugin enqueueing several assets, a child theme
    loading its parent's stylesheet -- sometimes with different version strings. The highest wins:
    a component cannot be older than the newest version it serves, and taking the lowest would
    report vulnerabilities that were already patched.
    """
    if not html:
        return []

    pattern = re.compile(_ASSET_PATH.format(kind=kind), re.IGNORECASE)
    by_slug: dict[str, Component] = {}
    extra_versions: dict[str, list[str]] = {}

    for match in pattern.finditer(html):
        slug = match.group(1).lower()
        path = match.group(2)

        version = None
        version_match = _ASSET_VERSION.search(path)
        if version_match:
            version = version_match.group(1)

        asset_path = f"/wp-content/{kind}/{slug}/{path}"
        evidence = urljoin(base_url, asset_path) if base_url else asset_path

        existing = by_slug.get(slug)
        if existing is None:
            by_slug[slug] = Component(
                kind="plugin" if kind == "plugins" else "theme",
                slug=slug,
                version=version,
                evidence=evidence,
            )
            extra_versions[slug] = [version] if version else []
            continue

        if version:
            if version not in extra_versions[slug]:
                extra_versions[slug].append(version)
            if existing.version is None or compare_versions(version, existing.version) > 0:
                existing.version = version
                existing.evidence = evidence

    return list(by_slug.values())


def fingerprint(html: str, headers: dict[str, str] | None = None, base_url: str | None = None) -> Fingerprint:
    """Identify WordPress, its version and its components from one page."""
    result = Fingerprint()
    html = html or ""
    headers = headers or {}
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items())

    if not html and not header_text:
        return result

    for pattern, label in _SIGNALS:
        if pattern.search(html):
            result.signals.append(label)

    # A cache or page builder can strip every marker out of the HTML; the headers remain.
    for key, value in headers.items():
        lowered = key.lower()
        if lowered == "x-pingback" and "xmlrpc.php" in value:
            result.signals.append("X-Pingback header")
        if lowered == "link" and "api.w.org" in value:
            result.signals.append("REST API Link header")

    result.is_wordpress = bool(result.signals)

    for label, pattern in _VERSION_SOURCES:
        match = pattern.search(html)
        if match:
            result.version = match.group(1)
            result.version_source = label
            break

    result.plugins = extract_components(html, "plugins", base_url)
    result.themes = extract_components(html, "themes", base_url)
    return result
