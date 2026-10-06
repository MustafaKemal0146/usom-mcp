"""User watch list (own SQLite file) and the checks that run against the cache."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from .api import UpstreamError
from .models import (
    ErrorInfo,
    ErrorInfoWithValue,
    Match,
    WatchAddResult,
    WatchEntry,
    WatchItemReport,
    WatchList,
    WatchRemoveResult,
    WatchReport,
)
from .normalize import Indicator, InvalidInputError, normalize_indicator
from .service import Service
from .store import Threat, parse_row

MAX_WATCH_ITEMS = 5000
_LISTED_BELOW_LIMIT = 50
_SCHEMA = """
CREATE TABLE IF NOT EXISTS watch_items (
    value TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT,
    added_at TEXT NOT NULL,
    last_checked_at TEXT,
    last_ids TEXT NOT NULL DEFAULT '[]'
);
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class WatchStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._init_done = False

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        if not self._init_done:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path) as conn:
                conn.executescript(_SCHEMA)
            self._init_done = True
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def count(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM watch_items").fetchone()[0])

    def add(self, ind: Indicator, label: str | None) -> WatchEntry | None:
        """Insert; ``None`` if the value is already watched."""
        added = _now_iso()
        with self._conn() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO watch_items(value, kind, label, added_at) VALUES (?,?,?,?)",
                (ind.value, ind.kind, label, added),
            )
            if cursor.rowcount == 0:
                return None
        return WatchEntry(value=ind.value, kind=ind.kind, label=label, added_at=added)

    def remove(self, value: str) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM watch_items WHERE value = ?", (value,)).rowcount > 0

    def entries(self) -> list[WatchEntry]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM watch_items ORDER BY added_at, value").fetchall()
        return [_entry(r) for r in rows]

    def get(self, value: str) -> sqlite3.Row | None:
        with self._conn() as conn:
            row: sqlite3.Row | None = conn.execute(
                "SELECT * FROM watch_items WHERE value = ?", (value,)
            ).fetchone()
        return row

    def record_check(self, value: str, ids: list[int]) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE watch_items SET last_checked_at = ?, last_ids = ? WHERE value = ?",
                (_now_iso(), json.dumps(sorted(ids)), value),
            )


def _entry(row: sqlite3.Row) -> WatchEntry:
    return WatchEntry(
        value=row["value"],
        kind=row["kind"],
        label=row["label"],
        added_at=row["added_at"],
        last_checked_at=row["last_checked_at"],
    )


class WatchService:
    def __init__(self, store: WatchStore, service: Service) -> None:
        self.store = store
        self.service = service

    # -- list management --------------------------------------------------------------
    async def add(self, values: list[str], label: str | None = None) -> WatchAddResult:
        added: list[WatchEntry] = []
        present: list[str] = []
        rejected: list[ErrorInfoWithValue] = []
        room = MAX_WATCH_ITEMS - await asyncio.to_thread(self.store.count)
        for raw in values:
            try:
                ind = normalize_indicator(raw)
            except InvalidInputError as exc:
                rejected.append(
                    ErrorInfoWithValue(input=str(raw)[:200], message=str(exc), hint=exc.hint)
                )
                continue
            if len(added) >= room:
                rejected.append(
                    ErrorInfoWithValue(
                        input=str(raw)[:200], message=f"watch list is full ({MAX_WATCH_ITEMS})"
                    )
                )
                continue
            entry = await asyncio.to_thread(self.store.add, ind, label)
            if entry is None:
                present.append(ind.value)
            else:
                added.append(entry)
        total = await asyncio.to_thread(self.store.count)
        return WatchAddResult(added=added, already_present=present, rejected=rejected, total=total)

    async def remove(self, values: list[str]) -> WatchRemoveResult:
        removed: list[str] = []
        missing: list[str] = []
        rejected: list[ErrorInfoWithValue] = []
        for raw in values:
            try:
                value = normalize_indicator(raw).value
            except InvalidInputError as exc:
                rejected.append(
                    ErrorInfoWithValue(input=str(raw)[:200], message=str(exc), hint=exc.hint)
                )
                continue
            if await asyncio.to_thread(self.store.remove, value):
                removed.append(value)
            else:
                missing.append(value)
        total = await asyncio.to_thread(self.store.count)
        return WatchRemoveResult(removed=removed, not_found=missing, rejected=rejected, total=total)

    async def list_entries(self) -> WatchList:
        entries = await asyncio.to_thread(self.store.entries)
        return WatchList(total=len(entries), entries=entries)

    # -- checking ---------------------------------------------------------------------
    async def check(self, value: str | None = None) -> WatchReport:
        svc = self.service
        svc.sync.ensure_fresh()
        live = not svc.cache_usable()
        origin: Literal["cache", "live"] = "live" if live else "cache"
        envelope = svc._envelope(origin)
        if value is not None:
            try:
                canonical = normalize_indicator(value).value
            except InvalidInputError as exc:
                return _report_error(envelope, "invalid_input", str(exc), exc.hint)
            row = await asyncio.to_thread(self.store.get, canonical)
            if row is None:
                return _report_error(
                    envelope,
                    "invalid_input",
                    f"{canonical!r} is not in the watch list",
                    "add it with watch_add, or use check_url / check_domain / check_ip",
                )
            entries = [_entry(row)]
        else:
            entries = await asyncio.to_thread(self.store.entries)
        await svc._refresh_labels()
        items: list[WatchItemReport] = []
        for entry in entries:
            items.append(await self._check_entry(entry, live))
        note = ""
        if not entries:
            note = "The watch list is empty; add domains, IPs or CIDR networks with watch_add."
        elif live:
            note = "Answered from the live USOM API (local cache building); results may be partial."
        return WatchReport(
            checked=len(items),
            listed=sum(i.status == "listed" for i in items),
            clean=sum(i.status == "clean" for i in items),
            unknown=sum(i.status == "unknown" for i in items),
            items=items,
            note=note,
            **envelope,
        )

    async def _check_entry(self, entry: WatchEntry, live: bool) -> WatchItemReport:
        svc = self.service
        ind = normalize_indicator(entry.value)
        matches: list[Match] = []
        below: list[Match] = []
        below_total = 0
        warnings: list[str] = []
        try:
            if ind.kind == "domain":
                matches = await svc._match_domain(ind, live)
                below_total, below_threats = await self._under_domain(ind.value, live)
                below = [svc.to_match(t, "subdomain") for t in below_threats]
            elif ind.kind == "ip":
                matches = await svc._match_ip(ind, live)
            elif ind.kind == "url":
                matches = await svc._match_url(ind, live)
            else:
                if live:
                    warnings.append("CIDR networks cannot be checked until the cache is ready")
                    return self._report(entry, "unknown", [], [], 0, [], warnings)
                threats = await asyncio.to_thread(svc.store.find_ips_within_network, ind.value)
                below = [svc.to_match(t, "cidr") for t in threats]
                below_total = len(below)
        except UpstreamError as exc:
            warnings.append(f"lookup failed: {exc}")
            return self._report(entry, "unknown", [], [], 0, [], warnings)
        ids = sorted({m.usom_id for m in matches} | {m.usom_id for m in below})
        row = await asyncio.to_thread(self.store.get, entry.value)
        previous = set(json.loads(row["last_ids"])) if row is not None else set()
        new_ids = [i for i in ids if i not in previous]
        await asyncio.to_thread(self.store.record_check, entry.value, ids)
        status: Literal["listed", "clean"] = "listed" if matches or below else "clean"
        return self._report(
            entry, status, matches, below[:_LISTED_BELOW_LIMIT], below_total, new_ids, warnings
        )

    async def _under_domain(self, domain: str, live: bool) -> tuple[int, list[Threat]]:
        if not live:
            return await asyncio.to_thread(self.service.store.find_under_domain, domain)
        page = await self.service.client.list_addresses(q=f".{domain}", per_page=100)
        rows = [parse_row(r) for r in page.rows]
        found = [t for t in rows if t is not None and (t.host or "").endswith(f".{domain}")]
        return len(found), found

    @staticmethod
    def _report(
        entry: WatchEntry,
        status: Literal["listed", "clean", "unknown"],
        matches: list[Match],
        below: list[Match],
        below_total: int,
        new_ids: list[int],
        warnings: list[str],
    ) -> WatchItemReport:
        return WatchItemReport(
            value=entry.value,
            kind=entry.kind,
            label=entry.label,
            status=status,
            matches=matches,
            listed_below=below,
            listed_below_total=below_total,
            new_since_last_check=new_ids,
            warnings=warnings,
        )


def _report_error(
    envelope: dict[str, object], code: Literal["invalid_input"], message: str, hint: str | None
) -> WatchReport:
    return WatchReport(
        checked=0,
        listed=0,
        clean=0,
        unknown=0,
        items=[],
        error=ErrorInfo(code=code, message=message, hint=hint),
        **envelope,  # type: ignore[arg-type]
    )
