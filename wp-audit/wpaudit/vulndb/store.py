"""The local vulnerability database.

SQLite, because the whole point is that a scan does not depend on a third party being up: the feed
is downloaded once, indexed by component slug, and every scan afterwards is a local lookup. That
also makes the tool usable on a schedule -- `wp-audit update` in a nightly cron, scans whenever you
like -- and the same database can be copied to a machine with no internet access at all.

Freshness is part of the result, not a detail. A scan against a database that is three months old
is not a clean bill of health, so the age travels with every report and the CLI warns about it.
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..models import VulnerabilityMatch
from ..versions import version_in_range
from .sources import VulnRecord

SCHEMA_VERSION = "1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability (
    source           TEXT NOT NULL,
    vuln_id          TEXT NOT NULL,
    software_type    TEXT NOT NULL,
    slug             TEXT NOT NULL,
    title            TEXT,
    cve              TEXT,
    cvss_score       REAL,
    cvss_rating      TEXT,
    published        TEXT,
    references_json  TEXT,
    patched          INTEGER,
    patched_versions TEXT,
    from_version     TEXT,
    from_inclusive   INTEGER,
    to_version       TEXT,
    to_inclusive     INTEGER
);

-- Every scan lookup is "all advisories for this component", so this index is the difference
-- between a scan taking milliseconds and scanning a table of a hundred thousand rows per plugin.
CREATE INDEX IF NOT EXISTS idx_vulnerability_component
    ON vulnerability (software_type, slug);
"""


def default_db_path() -> Path:
    """Where the database lives unless told otherwise (XDG cache dir on Linux/macOS)."""
    env = os.environ.get("WP_AUDIT_DB")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "wp-audit" / "vulndb.sqlite"


@dataclass
class DatabaseInfo:
    path: str
    exists: bool
    record_count: int = 0
    component_count: int = 0
    sources: list[str] = field(default_factory=list)
    updated_at: str | None = None
    age_hours: float | None = None
    attribution: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "exists": self.exists,
            "record_count": self.record_count,
            "component_count": self.component_count,
            "sources": self.sources,
            "updated_at": self.updated_at,
            "age_hours": round(self.age_hours, 1) if self.age_hours is not None else None,
            "attribution": self.attribution,
        }


class VulnerabilityDatabase:
    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.path = Path(path) if path else default_db_path()
        self._connection: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------------------------

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

    def __enter__(self) -> VulnerabilityDatabase:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- writing -----------------------------------------------------------------------------

    def replace_source(self, source: str, records: Iterable[VulnRecord], *, attribution: str = "") -> int:
        """Swap in a fresh copy of one source's data.

        Replacing rather than merging is what keeps a withdrawn advisory from living forever in
        somebody's cache. It happens inside one transaction, so an update that dies halfway leaves
        the previous database intact rather than an empty one.
        """
        connection = self.connection
        count = 0
        with connection:
            connection.execute("DELETE FROM vulnerability WHERE source = ?", (source,))
            for record in records:
                connection.execute(
                    """
                    INSERT INTO vulnerability (
                        source, vuln_id, software_type, slug, title, cve, cvss_score, cvss_rating,
                        published, references_json, patched, patched_versions,
                        from_version, from_inclusive, to_version, to_inclusive
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record.source,
                        record.vuln_id,
                        record.software_type,
                        record.slug,
                        record.title,
                        record.cve,
                        record.cvss_score,
                        record.cvss_rating,
                        record.published,
                        "\n".join(record.references),
                        int(record.patched),
                        "\n".join(record.patched_versions),
                        record.from_version,
                        int(record.from_inclusive),
                        record.to_version,
                        int(record.to_inclusive),
                    ),
                )
                count += 1

            self._set_meta(connection, f"updated_at:{source}", _now())
            self._set_meta(connection, f"count:{source}", str(count))
            self._set_meta(connection, "schema_version", SCHEMA_VERSION)
            if attribution:
                self._set_meta(connection, f"attribution:{source}", attribution)
        return count

    @staticmethod
    def _set_meta(connection: sqlite3.Connection, key: str, value: str) -> None:
        connection.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # -- reading -----------------------------------------------------------------------------

    def match(self, software_type: str, slug: str, version: str | None) -> list[VulnerabilityMatch]:
        """Advisories whose affected range covers this version of this component.

        With no version there is no match to make. That is reported by the caller as an unknown
        rather than as a clean result, because "we could not read the version" and "there is
        nothing wrong" are different things to tell a customer.
        """
        if not version or not slug:
            return []

        rows = self.connection.execute(
            "SELECT * FROM vulnerability WHERE software_type = ? AND slug = ?",
            (software_type, slug.lower()),
        ).fetchall()

        matches: dict[tuple[str, str], VulnerabilityMatch] = {}
        for row in rows:
            if not version_in_range(
                version,
                row["from_version"],
                bool(row["from_inclusive"]),
                row["to_version"],
                bool(row["to_inclusive"]),
            ):
                continue
            # One advisory can cover several ranges of the same component; report it once.
            key = (row["source"], row["vuln_id"])
            if key in matches:
                continue
            patched_versions = [v for v in (row["patched_versions"] or "").split("\n") if v]
            matches[key] = VulnerabilityMatch(
                source=row["source"],
                vuln_id=row["vuln_id"],
                title=row["title"] or "",
                cve=row["cve"],
                cvss_score=row["cvss_score"],
                cvss_rating=row["cvss_rating"],
                patched_in=patched_versions[0] if patched_versions else None,
                published=row["published"],
                references=[r for r in (row["references_json"] or "").split("\n") if r],
            )

        return sorted(
            matches.values(),
            key=lambda m: (-(m.cvss_score or 0.0), m.title),
        )

    def info(self) -> DatabaseInfo:
        if not self.path.exists():
            return DatabaseInfo(path=str(self.path), exists=False)

        connection = self.connection
        record_count = connection.execute("SELECT COUNT(*) FROM vulnerability").fetchone()[0]
        component_count = connection.execute(
            "SELECT COUNT(DISTINCT software_type || '/' || slug) FROM vulnerability"
        ).fetchone()[0]
        rows = connection.execute("SELECT key, value FROM meta").fetchall()
        meta = {row["key"]: row["value"] for row in rows}

        sources = sorted(
            key.split(":", 1)[1] for key in meta if key.startswith("updated_at:")
        )
        timestamps = [meta[f"updated_at:{source}"] for source in sources]
        updated_at = min(timestamps) if timestamps else None
        attributions = [meta[key] for key in sorted(meta) if key.startswith("attribution:")]

        age_hours = None
        if updated_at:
            try:
                parsed = datetime.fromisoformat(updated_at)
                age_hours = (datetime.now(timezone.utc) - parsed).total_seconds() / 3600
            except ValueError:
                age_hours = None

        return DatabaseInfo(
            path=str(self.path),
            exists=True,
            record_count=record_count,
            component_count=component_count,
            sources=sources,
            updated_at=updated_at,
            age_hours=age_hours,
            attribution=" ".join(attributions),
        )

    def is_stale(self, max_age_hours: float = 24.0) -> bool:
        info = self.info()
        if not info.exists or info.record_count == 0 or info.age_hours is None:
            return True
        return info.age_hours > max_age_hours


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iter_progress(records: Iterable[VulnRecord], every: int = 5000) -> Iterator[VulnRecord]:
    """Pass records through, printing progress -- the full feed takes a moment to index."""
    start = time.time()
    for index, record in enumerate(records, start=1):
        if index % every == 0:
            print(f"  indexed {index:,} records ({time.time() - start:.0f}s)", flush=True)
        yield record
