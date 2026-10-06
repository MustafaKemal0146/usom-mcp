"""Cache synchronisation: first-run full download, then incremental updates."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from .api import MAX_PER_PAGE, UpstreamError, UsomClient
from .labels import DICTIONARY_ENDPOINTS
from .store import Store, Threat, parse_row

log = logging.getLogger("usom_mcp.sync")

CacheState = Literal["empty", "building", "ready", "refreshing"]
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class SyncRejectedError(Exception):
    """A sync result was refused (empty or incomplete) and the live cache left untouched."""


@dataclass(slots=True)
class Progress:
    phase: str = ""
    pages_done: int = 0
    pages_total: int = 0


@dataclass(slots=True)
class SyncConfig:
    ttl_seconds: float = 3600.0
    full_interval_seconds: float = 7 * 86400.0
    drift_recheck_seconds: float = 86400.0
    overlap_hours: float = 48.0
    page_delay_seconds: float = 1.0
    min_retry_seconds: float = 60.0
    resume_window_seconds: float = 6 * 3600.0
    completeness_ratio: float = 0.95
    per_page: int = MAX_PER_PAGE


@dataclass
class SyncManager:
    store: Store
    client: UsomClient
    config: SyncConfig = field(default_factory=SyncConfig)
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    #: when False, only explicit ``start()`` calls sync (offline mode, USOM_MCP_NO_SYNC=1)
    auto_refresh: bool = True
    _task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _progress: Progress = field(default_factory=Progress, init=False)
    _last_attempt: float | None = field(default=None, init=False)
    _last_error: str | None = field(default=None, init=False)

    @property
    def staging_path(self) -> Path:
        return self.store.path.with_name(self.store.path.name + ".new")

    # -- state ------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def _has_data(self) -> bool:
        return self.store.path.exists() and self.store.has_rows()

    def state(self) -> CacheState:
        has_data = self._has_data()
        if self.running:
            return "refreshing" if has_data else "building"
        return "ready" if has_data else "empty"

    def info(self) -> dict[str, Any]:
        """Snapshot used by every tool response and by ``stats``."""
        meta = self.store.all_meta() if self.store.path.exists() else {}
        has_data = self._has_data()
        last_success = float(meta["last_success"]) if "last_success" in meta else None
        age = None if last_success is None else max(0.0, self.clock() - last_success)
        error = self._last_error or meta.get("last_error")
        stale = bool(
            has_data
            and age is not None
            and (age > 86400 or (age > self.config.ttl_seconds and error))
        )
        severity = (
            "high"
            if has_data and age is not None and age > 86400
            else ("normal" if stale else None)
        )
        return {
            "state": self.state(),
            "records": int(meta.get("record_count", "0")) if has_data else 0,
            "last_sync": None
            if last_success is None
            else datetime.fromtimestamp(last_success, UTC).isoformat(timespec="seconds"),
            "age_seconds": None if age is None else round(age),
            "ttl_seconds": int(self.config.ttl_seconds),
            "stale": stale,
            "stale_severity": severity,
            "last_error": error,
            "progress": None
            if not self.running
            else {
                "phase": self._progress.phase,
                "pages_done": self._progress.pages_done,
                "pages_total": self._progress.pages_total,
            },
            "remote_total": int(meta["remote_total"]) if "remote_total" in meta else None,
            "drift": int(meta["drift"]) if "drift" in meta else None,
            "skipped_malformed": int(meta.get("skipped_malformed", "0")),
            "last_full_sync": _iso(meta.get("last_full_sync")),
            "last_incremental_sync": _iso(meta.get("last_incremental_sync")),
        }

    # -- scheduling -------------------------------------------------------------------
    def ensure_fresh(self) -> None:
        """Non-blocking: start a background sync if the cache is empty or past its TTL."""
        if self.running or not self.auto_refresh:
            return
        now = self.clock()
        if (
            self._last_attempt is not None
            and now - self._last_attempt < self.config.min_retry_seconds
        ):
            return
        meta = self.store.all_meta() if self.store.path.exists() else {}
        last_success = float(meta["last_success"]) if "last_success" in meta else None
        if (
            not self._has_data()
            or last_success is None
            or now - last_success > self.config.ttl_seconds
        ):
            self.start()

    def start(self) -> None:
        if self.running:
            return
        self._last_attempt = self.clock()
        self._task = asyncio.get_running_loop().create_task(self._run_guarded())

    async def wait(self) -> None:
        """Await the running sync (used by tests and the CLI ``--sync`` mode)."""
        if self._task is not None:
            await self._task

    async def cancel(self) -> None:
        """Stop a running background sync (server shutdown)."""
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def _run_guarded(self) -> None:
        try:
            await self.run_once()
        except asyncio.CancelledError:
            raise
        except (UpstreamError, SyncRejectedError, OSError) as exc:
            self._record_error(f"{type(exc).__name__}: {exc}")
            log.warning("sync failed: %s", exc)
        except Exception as exc:  # keep the server alive whatever happens in the background
            self._record_error(f"unexpected {type(exc).__name__}: {exc}")
            log.exception("unexpected sync failure")

    def _record_error(self, message: str) -> None:
        self._last_error = message
        if self.store.path.exists():
            self.store.set_meta(last_error=message)

    async def run_once(self) -> None:
        if await asyncio.to_thread(self.store.reset_if_unusable):
            log.warning("discarded an unusable cache; rebuilding")
        await asyncio.to_thread(self.store.init, wal=False)
        meta = await asyncio.to_thread(self.store.all_meta)
        count = await asyncio.to_thread(self.store.count)
        now = self.clock()
        last_full = float(meta["last_full_sync"]) if "last_full_sync" in meta else None
        need_full = (
            count == 0
            or last_full is None
            or meta.get("needs_full") == "1"
            or now - last_full > self.config.full_interval_seconds
        )
        if need_full:
            await self.full_sync()
            await self.incremental_sync()
        else:
            await self.incremental_sync()
        self._last_error = None
        await asyncio.to_thread(self.store.set_meta, last_error=None)

    # -- helpers ----------------------------------------------------------------------
    def _ingest(self, rows: list[Any]) -> tuple[list[Threat], int]:
        threats: list[Threat] = []
        skipped = 0
        for raw in rows:
            threat = parse_row(raw)
            if threat is None:
                skipped += 1
            else:
                threats.append(threat)
        return threats, skipped

    async def _refresh_dictionaries(self, target: Store) -> None:
        for kind, endpoint in DICTIONARY_ENDPOINTS.items():
            try:
                models = await self.client.get_dictionary(endpoint)
            except UpstreamError as exc:
                log.info("dictionary %s not refreshed: %s", kind, exc)
                continue
            entries = {
                m["id"]: (str(m.get("en_title") or m["id"]), str(m.get("tr_title") or m["id"]))
                for m in models
            }
            await asyncio.to_thread(target.replace_dictionary, kind, entries)

    # -- full sync --------------------------------------------------------------------
    async def full_sync(self) -> None:
        staging = Store(self.staging_path)
        await asyncio.to_thread(self._prepare_staging, staging)
        meta = await asyncio.to_thread(staging.all_meta)
        next_page = int(meta.get("full_next_page", "1"))
        skipped = int(meta.get("skipped_malformed", "0"))
        self._progress = Progress("full", next_page - 1, 0)
        page_no = next_page
        remote_total = int(meta.get("full_remote_total", "0"))
        async for page in self.client.iter_pages(
            start_page=next_page, per_page=self.config.per_page
        ):
            remote_total = page.total_count
            self._progress.pages_total = max(page.page_count, 1)
            if page.total_count == 0:
                raise SyncRejectedError("upstream reported an empty list; keeping existing cache")
            threats, bad = self._ingest(page.rows)
            skipped += bad
            await asyncio.to_thread(staging.upsert, threats)
            page_no += 1
            self._progress.pages_done = page_no - 1
            await asyncio.to_thread(
                staging.set_meta,
                full_next_page=str(page_no),
                full_remote_total=str(remote_total),
                skipped_malformed=str(skipped),
            )
            if self.config.page_delay_seconds:
                await self.sleep(self.config.page_delay_seconds)
        got = await asyncio.to_thread(staging.count)
        # Malformed rows are part of upstream's totalCount but never stored.
        if remote_total == 0 or got + skipped < remote_total * self.config.completeness_ratio:
            raise SyncRejectedError(
                f"full download incomplete: {got + skipped} of {remote_total} records; will resume"
            )
        await self._refresh_dictionaries(staging)
        await asyncio.to_thread(staging.refresh_breakdown)
        await asyncio.to_thread(staging.vacuum)
        now = self.clock()
        await asyncio.to_thread(
            staging.set_meta,
            record_count=str(got),
            last_full_sync=str(now),
            last_success=str(now),
            remote_total=str(remote_total),
            drift=str(got + skipped - remote_total),
            full_started=None,
            full_next_page=None,
            full_remote_total=None,
            needs_full=None,
            last_error=None,
        )
        await self._swap_in_staging()
        log.info("full sync complete: %d records", got)

    async def _swap_in_staging(self) -> None:
        for attempt in range(5):
            try:
                await asyncio.to_thread(os.replace, self.staging_path, self.store.path)
                return
            except PermissionError:  # Windows: a reader still has the old file open
                if attempt == 4:
                    raise
                await self.sleep(0.5 * (attempt + 1))

    def _prepare_staging(self, staging: Store) -> None:
        """Resume a recent partial download or start a fresh staging database."""
        now = self.clock()
        if self.staging_path.exists():
            staging.init(wal=False)
            started = staging.get_meta("full_started")
            if (
                started is not None
                and staging.get_meta("full_next_page") is not None
                and now - float(started) < self.config.resume_window_seconds
            ):
                return
            self.staging_path.unlink()
        staging.init(wal=False)
        staging.set_meta(full_started=str(now), full_next_page="1")

    # -- incremental sync -------------------------------------------------------------
    async def incremental_sync(self) -> None:
        max_date = await asyncio.to_thread(self.store.max_date)
        if max_date is None:
            raise SyncRejectedError("cannot run an incremental sync on an empty cache")
        since = datetime.strptime(max_date[:19], _DATE_FORMAT) - timedelta(
            hours=self.config.overlap_hours
        )
        self._progress = Progress("incremental", 0, 0)
        skipped_total = 0
        async for page in self.client.iter_pages(
            per_page=self.config.per_page, date_gte=since.strftime(_DATE_FORMAT)
        ):
            self._progress.pages_total = max(page.page_count, 1)
            threats, bad = self._ingest(page.rows)
            skipped_total += bad
            await asyncio.to_thread(self.store.upsert, threats)
            self._progress.pages_done += 1
            if self.config.page_delay_seconds:
                await self.sleep(self.config.page_delay_seconds)
        remote = await self.client.list_addresses(page=1, per_page=1)
        if remote.total_count == 0:
            raise SyncRejectedError("upstream reported an empty list; keeping existing cache")
        local = await asyncio.to_thread(self.store.count)
        meta = await asyncio.to_thread(self.store.all_meta)
        # Rows rejected as malformed at the last full sync are counted upstream but not stored.
        known_malformed = int(meta.get("skipped_malformed", "0"))
        drift = local + known_malformed - remote.total_count
        now = self.clock()
        last_full = float(meta.get("last_full_sync", "0"))
        needs_full = drift != 0 and now - last_full > self.config.drift_recheck_seconds
        await asyncio.to_thread(
            self.store.set_meta,
            last_incremental_sync=str(now),
            last_success=str(now),
            record_count=str(local),
            remote_total=str(remote.total_count),
            drift=str(drift),
            needs_full="1" if needs_full else None,
        )
        if skipped_total:
            log.info("incremental pass skipped %d malformed rows", skipped_total)
        await asyncio.to_thread(self.store.refresh_breakdown)
        await self._maybe_refresh_dictionaries(meta, now)

    async def _maybe_refresh_dictionaries(self, meta: dict[str, str], now: float) -> None:
        if now - float(meta.get("dictionaries_synced", "0")) < 86400:
            return
        await self._refresh_dictionaries(self.store)
        await asyncio.to_thread(self.store.set_meta, dictionaries_synced=str(now))


def _iso(epoch: str | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(float(epoch), UTC).isoformat(timespec="seconds")
