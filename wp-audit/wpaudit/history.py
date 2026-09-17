"""Scan history: what each site looked like last time.

Without this the tool can only answer "what is wrong now", which means somebody has to read every
report in full to notice that anything changed. With it, the interesting question becomes cheap:
what is different since last time, in either direction.

It also keeps a component inventory per site, which is what lets `wp-audit update --alert-known`
answer the question an MSP actually cares about -- "does today's feed contain anything affecting a
plugin one of my customers runs" -- without re-scanning anybody.

Reports are stored whole, as JSON. They are small, it keeps old scans renderable after the finding
set changes, and it means a diff never depends on a schema migration.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import ScanReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    site              TEXT NOT NULL,
    scanned_at        TEXT NOT NULL,
    completed         INTEGER NOT NULL,
    score             INTEGER,
    grade             TEXT,
    wordpress_version TEXT,
    report_json       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_site ON scan (site, id);

-- The inventory, kept separately from the reports so a feed update can be checked against every
-- component ever seen without unpacking every stored scan.
CREATE TABLE IF NOT EXISTS component_seen (
    site      TEXT NOT NULL,
    kind      TEXT NOT NULL,
    slug      TEXT NOT NULL,
    version   TEXT,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (site, kind, slug)
);

CREATE TABLE IF NOT EXISTS core_seen (
    site      TEXT PRIMARY KEY,
    version   TEXT,
    last_seen TEXT NOT NULL
);
"""


def default_history_path() -> Path:
    env = os.environ.get("WP_AUDIT_HISTORY")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "wp-audit" / "history.sqlite"


def site_key(report_or_url: ScanReport | str) -> str:
    """The identity a site keeps between scans.

    The hostname, not the URL: a site that starts redirecting to www, or gets HTTPS for the first
    time, is still the same customer site and its history should not fork the day that happens.
    """
    if isinstance(report_or_url, ScanReport):
        url = report_or_url.final_url or report_or_url.url
    else:
        url = report_or_url
    if "://" not in url:
        url = "https://" + url
    host = urlsplit(url).hostname or url
    return host.lower()


@dataclass
class ComponentRecord:
    site: str
    kind: str
    slug: str
    version: str | None
    last_seen: str


class ScanHistory:
    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.path = Path(path) if path else default_history_path()
        self._connection: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(str(self.path))
            self._connection.row_factory = sqlite3.Row
            self._connection.executescript(_SCHEMA)
        return self._connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> ScanHistory:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- writing -----------------------------------------------------------------------------

    def record(self, report: ScanReport) -> int:
        """Store a scan and refresh the site's component inventory.

        A scan that could not be completed is stored too: "this site has been unreachable for four
        days" is something worth being able to see, and dropping the failures would make the
        history quietly optimistic.
        """
        site = site_key(report)
        now = report.scanned_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
        connection = self.connection

        with connection:
            cursor = connection.execute(
                """
                INSERT INTO scan (site, scanned_at, completed, score, grade, wordpress_version, report_json)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    site,
                    now,
                    int(report.completed),
                    report.score,
                    report.grade,
                    report.wordpress_version,
                    json.dumps(report.to_dict()),
                ),
            )

            if report.completed:
                if report.wordpress_version:
                    connection.execute(
                        "INSERT INTO core_seen (site, version, last_seen) VALUES (?,?,?) "
                        "ON CONFLICT(site) DO UPDATE SET version=excluded.version, last_seen=excluded.last_seen",
                        (site, report.wordpress_version, now),
                    )
                for component in report.components:
                    connection.execute(
                        """
                        INSERT INTO component_seen (site, kind, slug, version, last_seen)
                        VALUES (?,?,?,?,?)
                        ON CONFLICT(site, kind, slug) DO UPDATE SET
                            version=excluded.version, last_seen=excluded.last_seen
                        """,
                        (site, component.kind, component.slug.lower(), component.version, now),
                    )

        return int(cursor.lastrowid)

    def prune(self, keep_per_site: int = 50) -> int:
        """Keep the most recent scans per site and drop the rest.

        A daily scan of a hundred sites is 36,500 stored reports a year; the diff only ever reads
        the previous one, and nobody opens a report from eight months ago.
        """
        removed = 0
        connection = self.connection
        with connection:
            for row in connection.execute("SELECT DISTINCT site FROM scan").fetchall():
                cursor = connection.execute(
                    """
                    DELETE FROM scan WHERE site = ? AND id NOT IN (
                        SELECT id FROM scan WHERE site = ? ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (row["site"], row["site"], keep_per_site),
                )
                removed += cursor.rowcount if cursor.rowcount > 0 else 0
        return removed

    # -- reading -----------------------------------------------------------------------------

    def previous(self, site: str, before_id: int | None = None) -> dict[str, Any] | None:
        """The last completed scan of this site, optionally before a given row.

        Incomplete scans are skipped when looking for something to compare against: diffing
        against a scan that never reached the site would report every finding as newly resolved.
        """
        if before_id is None:
            row = self.connection.execute(
                "SELECT report_json FROM scan WHERE site = ? AND completed = 1 ORDER BY id DESC LIMIT 1",
                (site,),
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT report_json FROM scan WHERE site = ? AND completed = 1 AND id < ? "
                "ORDER BY id DESC LIMIT 1",
                (site, before_id),
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def trend(self, site: str, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT scanned_at, completed, score, grade, wordpress_version FROM scan "
            "WHERE site = ? ORDER BY id DESC LIMIT ?",
            (site, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def sites(self) -> list[str]:
        rows = self.connection.execute("SELECT DISTINCT site FROM scan ORDER BY site").fetchall()
        return [row["site"] for row in rows]

    def components(self) -> list[ComponentRecord]:
        rows = self.connection.execute(
            "SELECT site, kind, slug, version, last_seen FROM component_seen ORDER BY site, kind, slug"
        ).fetchall()
        return [ComponentRecord(**dict(row)) for row in rows]

    def cores(self) -> list[tuple[str, str]]:
        rows = self.connection.execute(
            "SELECT site, version FROM core_seen WHERE version IS NOT NULL ORDER BY site"
        ).fetchall()
        return [(row["site"], row["version"]) for row in rows]

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM scan").fetchone()[0])
