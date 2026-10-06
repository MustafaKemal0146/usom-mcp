"""SQLite cache of the USOM address list."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .api import VALID_TYPES
from .normalize import canonical_stored

SCHEMA_VERSION = "2"
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY,
    value TEXT NOT NULL,
    host TEXT,
    rhost TEXT,
    type TEXT NOT NULL,
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    connection_type TEXT NOT NULL,
    criticality INTEGER NOT NULL,
    date TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threats_value ON threats(value);
-- host is stored only for URL rows (for the others it equals value)
CREATE INDEX IF NOT EXISTS idx_threats_host ON threats(host) WHERE host IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threats_rhost ON threats(rhost);
CREATE INDEX IF NOT EXISTS idx_threats_date ON threats(date);
CREATE TABLE IF NOT EXISTS ip_ranges (
    threat_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    start BLOB NOT NULL,
    "end" BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ip_ranges_lookup ON ip_ranges(version, start, "end");
CREATE INDEX IF NOT EXISTS idx_ip_ranges_threat ON ip_ranges(threat_id);
CREATE TABLE IF NOT EXISTS dictionaries (
    kind TEXT NOT NULL, id TEXT NOT NULL, en TEXT NOT NULL, tr TEXT NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


@dataclass(frozen=True, slots=True)
class Threat:
    id: int
    value: str
    host: str | None
    type: str
    category: str
    source: str
    connection_type: str
    criticality: int
    date: str


def parse_row(raw: Any) -> Threat | None:
    """Validate one API record; ``None`` means malformed (caller counts it)."""
    if not isinstance(raw, dict):
        return None
    id_, url, type_ = raw.get("id"), raw.get("url"), raw.get("type")
    category, source = raw.get("desc"), raw.get("source")
    conn, crit, date = raw.get("connectiontype"), raw.get("criticality_level"), raw.get("date")
    if isinstance(id_, bool) or not isinstance(id_, int):
        return None
    if isinstance(crit, bool) or not isinstance(crit, int):
        return None
    if not all(isinstance(v, str) for v in (url, type_, category, source, conn, date)):
        return None
    assert isinstance(url, str) and isinstance(type_, str) and isinstance(date, str)
    if type_ not in VALID_TYPES or not _DATE_RE.match(date):
        return None
    canonical = canonical_stored(url, type_)
    if canonical is None:
        return None
    value, host = canonical
    return Threat(
        id=id_,
        value=value,
        host=host,
        type=type_,
        category=str(category),
        source=str(source),
        connection_type=str(conn),
        criticality=crit,
        date=date,
    )


def _derive_host(value: str, type_: str, stored: str | None) -> str | None:
    """``host`` is only stored for URL rows; for the rest it is the value (networks: none)."""
    if type_ == "url":
        return stored
    return None if "/" in value else value


def _threat_from_row(row: sqlite3.Row) -> Threat:
    value, type_ = row["value"], row["type"]
    return Threat(
        id=row["id"],
        value=value,
        host=_derive_host(value, type_, row["host"]),
        type=type_,
        category=row["category"],
        source=row["source"],
        connection_type=row["connection_type"],
        criticality=row["criticality"],
        date=row["date"],
    )


def _placeholders(n: int) -> str:
    return ",".join("?" * n)


class Store:
    """Thin wrapper opening a short-lived connection per call (thread-safe by design)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self, *, wal: bool = True) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            if wal:
                conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta(k, v) VALUES ('schema_version', ?)", (SCHEMA_VERSION,)
            )

    # -- meta -------------------------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
        return str(row["v"]) if row else default

    def set_meta(self, **items: str | None) -> None:
        with self._conn() as conn:
            for key, value in items.items():
                if value is None:
                    conn.execute("DELETE FROM meta WHERE k = ?", (key,))
                else:
                    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", (key, value))

    def all_meta(self) -> dict[str, str]:
        with self._conn() as conn:
            return {r["k"]: r["v"] for r in conn.execute("SELECT k, v FROM meta")}

    # -- writes -----------------------------------------------------------------------
    def upsert(self, threats: Iterable[Threat]) -> int:
        rows = list(threats)
        with self._conn() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO threats"
                "(id, value, host, rhost, type, category, source, connection_type,"
                " criticality, date) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        t.id,
                        t.value,
                        t.host if t.type == "url" else None,
                        t.host[::-1] if t.host else None,
                        t.type,
                        t.category,
                        t.source,
                        t.connection_type,
                        t.criticality,
                        t.date,
                    )
                    for t in rows
                ],
            )
            ids = [(t.id,) for t in rows]
            conn.executemany("DELETE FROM ip_ranges WHERE threat_id = ?", ids)
            ranges: list[tuple[int, int, bytes, bytes]] = []
            for t in rows:
                if t.host is None and "/" in t.value:
                    net = ipaddress.ip_network(t.value, strict=False)
                    ranges.append(
                        (
                            t.id,
                            net.version,
                            net.network_address.packed,
                            net.broadcast_address.packed,
                        )
                    )
            conn.executemany(
                'INSERT INTO ip_ranges(threat_id, version, start, "end") VALUES (?,?,?,?)', ranges
            )
        return len(rows)

    def replace_dictionary(self, kind: str, entries: dict[str, tuple[str, str]]) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM dictionaries WHERE kind = ?", (kind,))
            conn.executemany(
                "INSERT INTO dictionaries(kind, id, en, tr) VALUES (?,?,?,?)",
                [(kind, k, en, tr) for k, (en, tr) in entries.items()],
            )

    # -- reads ------------------------------------------------------------------------
    def count(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0])

    def has_rows(self) -> bool:
        """Cheap emptiness check (``COUNT(*)`` on 500k rows costs ~12 ms)."""
        try:
            with self._conn() as conn:
                return conn.execute("SELECT 1 FROM threats LIMIT 1").fetchone() is not None
        except sqlite3.DatabaseError:
            return False

    def vacuum(self) -> None:
        """Compact the file; descending-id inserts leave B-tree pages about half full."""
        conn = sqlite3.connect(self.path, timeout=60)
        try:
            conn.execute("VACUUM")
        finally:
            conn.close()

    def reset_if_unusable(self) -> bool:
        """Delete a cache that is corrupt or was written by another schema version."""
        if not self.path.exists():
            return False
        try:
            with self._conn() as conn:
                row = conn.execute("SELECT v FROM meta WHERE k = 'schema_version'").fetchone()
            usable = row is not None and row["v"] == SCHEMA_VERSION
        except sqlite3.DatabaseError:
            usable = False
        if not usable:
            self.path.unlink()
        return not usable

    def max_date(self) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT MAX(date) FROM threats").fetchone()
        return str(row[0]) if row and row[0] else None

    def dictionary(self, kind: str) -> dict[str, tuple[str, str]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT id, en, tr FROM dictionaries WHERE kind = ?", (kind,))
            return {r["id"]: (r["en"], r["tr"]) for r in rows}

    def find_values(self, values: Sequence[str]) -> list[Threat]:
        if not values:
            return []
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM threats WHERE value IN ({_placeholders(len(values))})",
                list(values),
            ).fetchall()
        return [_threat_from_row(r) for r in rows]

    def find_url_rows_for_host(self, host: str) -> list[Threat]:
        """Stored URL entries with a path on ``host`` (for prefix matching)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM threats WHERE host = ? AND type = 'url' AND value != host",
                (host,),
            ).fetchall()
        return [_threat_from_row(r) for r in rows]

    def find_ip_in_ranges(self, ip: str) -> list[Threat]:
        addr = ipaddress.ip_address(ip)
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT t.* FROM ip_ranges r JOIN threats t ON t.id = r.threat_id "
                'WHERE r.version = ? AND r.start <= ? AND r."end" >= ?',
                (addr.version, addr.packed, addr.packed),
            ).fetchall()
        return [_threat_from_row(r) for r in rows]

    def find_ips_within_network(self, network: str, limit: int = 500) -> list[Threat]:
        """Listed single IPs and listed networks overlapping ``network``."""
        net = ipaddress.ip_network(network, strict=False)
        start, end = net.network_address.packed, net.broadcast_address.packed
        types = ("ip",) if net.version == 4 else ("ip6",)
        out: list[Threat] = []
        with self._conn() as conn:
            for t in types:
                for r in conn.execute(
                    "SELECT * FROM threats WHERE type = ? AND instr(value, '/') = 0", (t,)
                ):
                    try:
                        packed = ipaddress.ip_address(r["value"]).packed
                    except ValueError:
                        continue
                    if len(packed) == len(start) and start <= packed <= end:
                        out.append(_threat_from_row(r))
                        if len(out) >= limit:
                            return out
            rows = conn.execute(
                "SELECT t.* FROM ip_ranges r JOIN threats t ON t.id = r.threat_id "
                'WHERE r.version = ? AND r.start <= ? AND r."end" >= ?',
                (net.version, end, start),
            ).fetchall()
        out.extend(_threat_from_row(r) for r in rows)
        return out[:limit]

    def find_under_domain(self, domain: str, limit: int = 200) -> tuple[int, list[Threat]]:
        """Entries whose host is a strict subdomain of ``domain`` (index range scan)."""
        prefix = domain[::-1] + "."
        upper = domain[::-1] + "/"  # '/' sorts right after '.'
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM threats WHERE rhost >= ? AND rhost < ?", (prefix, upper)
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM threats WHERE rhost >= ? AND rhost < ? ORDER BY date DESC LIMIT ?",
                (prefix, upper, limit),
            ).fetchall()
        return int(total), [_threat_from_row(r) for r in rows]

    def search(
        self,
        *,
        query: str | None = None,
        type: str | None = None,
        category: str | None = None,
        source: str | None = None,
        connection_type: str | None = None,
        max_criticality: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[Threat]]:
        where: list[str] = []
        args: list[Any] = []
        if query:
            where.append("instr(value, ?) > 0")
            args.append(query.lower())
        for column, value in (
            ("type", type),
            ("category", category),
            ("source", source),
            ("connection_type", connection_type),
        ):
            if value is not None:
                where.append(f"{column} = ?")
                args.append(value)
        if max_criticality is not None:
            where.append("criticality <= ?")
            args.append(max_criticality)
        if date_from is not None:
            where.append("date >= ?")
            args.append(date_from)
        if date_to is not None:
            where.append("date <= ?")
            args.append(date_to)
        clause = f" WHERE {' AND '.join(where)}" if where else ""
        with self._conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM threats{clause}", args).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM threats{clause} ORDER BY date DESC, id DESC LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
        return int(total), [_threat_from_row(r) for r in rows]

    def breakdown(self) -> dict[str, dict[str, int]]:
        """Counts per type/category/source; precomputed after each sync (the scan is slow)."""
        cached = self.get_meta("breakdown")
        if cached is not None:
            result: dict[str, dict[str, int]] = json.loads(cached)
            return result
        return self.refresh_breakdown()

    def refresh_breakdown(self) -> dict[str, dict[str, int]]:
        with self._conn() as conn:
            out: dict[str, dict[str, int]] = {}
            for column in ("type", "category", "source"):
                out[column] = {
                    r[0]: r[1]
                    for r in conn.execute(
                        f"SELECT {column}, COUNT(*) FROM threats GROUP BY {column} "
                        "ORDER BY COUNT(*) DESC"
                    )
                }
        self.set_meta(breakdown=json.dumps(out))
        return out
