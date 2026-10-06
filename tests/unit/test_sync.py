from __future__ import annotations

import httpx
import pytest

from tests.conftest import Clock, FakeUsom, make_row
from usom_mcp.store import Store
from usom_mcp.sync import SyncManager, SyncRejectedError


def _rows(n: int, start: int = 1, date: str = "2026-10-01 12:00:00") -> list[dict]:
    return [make_row(i, f"d{i}.example.com", date=date) for i in range(start, start + n)]


async def test_first_run_full_sync_populates_cache(
    fake: FakeUsom, sync: SyncManager, store: Store
) -> None:
    fake.rows = _rows(120)
    assert sync.state() == "empty"
    sync.start()
    assert sync.state() == "building"
    await sync.wait()
    assert sync.state() == "ready"
    assert store.count() == 120
    info = sync.info()
    assert info["remote_total"] == 120 and info["drift"] == 0 and info["stale"] is False
    assert info["last_full_sync"] and info["last_incremental_sync"]  # incremental runs after full
    assert not sync.staging_path.exists()  # swapped in atomically


async def test_full_sync_uses_per_page_and_pagecount(fake: FakeUsom, sync: SyncManager) -> None:
    fake.rows = _rows(120)
    sync.start()
    await sync.wait()
    paged = [c for c in fake.calls if c["path"] == "/api/address/index" and "date_gte" not in c]
    assert [c["page"] for c in paged if c["per-page"] == "50"] == ["1", "2", "3"]


async def test_incremental_adds_new_records_and_uses_overlap(
    fake: FakeUsom, sync: SyncManager, store: Store, clock: Clock
) -> None:
    fake.rows = _rows(10)
    sync.start()
    await sync.wait()
    fake.rows += [make_row(11, "new.example.com", date="2026-10-02 08:00:00")]
    clock.now += 7200
    fake.calls.clear()
    sync.start()
    await sync.wait()
    assert store.count() == 11
    gte = next(c["date_gte"] for c in fake.calls if "date_gte" in c)
    assert gte == "2026-09-29 12:00:00"  # max stored date (2026-10-01 12:00) minus 48 h


async def test_empty_upstream_never_wipes_existing_cache(
    fake: FakeUsom, sync: SyncManager, store: Store, clock: Clock
) -> None:
    fake.rows = _rows(10)
    sync.start()
    await sync.wait()
    fake.rows = []
    clock.now += 7200
    sync.start()
    await sync.wait()
    assert store.count() == 10
    info = sync.info()
    assert "empty list" in (info["last_error"] or "")
    assert info["state"] == "ready"


async def test_empty_upstream_on_first_run_is_rejected(fake: FakeUsom, sync: SyncManager) -> None:
    fake.rows = []
    sync.start()
    await sync.wait()
    assert sync.state() == "empty"
    assert "empty list" in (sync.info()["last_error"] or "")


async def test_malformed_rows_are_skipped_and_counted(
    fake: FakeUsom, sync: SyncManager, store: Store
) -> None:
    good = _rows(5)
    bad = [
        {"id": 100},
        {**make_row(101, "x.com"), "date": "nope"},
        "garbage",
        {**make_row(102, "x.com"), "type": "zzz"},
    ]
    fake.rows = good + bad  # type: ignore[operator]
    sync.start()
    await sync.wait()
    assert store.count() == 5
    assert sync.info()["skipped_malformed"] == 4 and sync.info()["drift"] == 0


async def test_upstream_down_after_cache_built_marks_stale_after_ttl(
    fake: FakeUsom, sync: SyncManager, clock: Clock
) -> None:
    fake.rows = _rows(5)
    sync.start()
    await sync.wait()
    assert sync.info()["stale"] is False
    fake.unreachable = True
    clock.now += 3 * 3600  # past the 1 h TTL
    sync.ensure_fresh()
    await sync.wait()
    info = sync.info()
    assert info["stale"] is True and info["stale_severity"] == "normal"
    assert "giving up" in info["last_error"]
    assert info["state"] == "ready" and info["records"] == 5  # old data still served
    clock.now += 2 * 86400
    assert sync.info()["stale_severity"] == "high"


async def test_fresh_cache_is_not_stale_even_after_failed_refresh_attempt(
    fake: FakeUsom, sync: SyncManager, clock: Clock
) -> None:
    fake.rows = _rows(5)
    sync.start()
    await sync.wait()
    fake.unreachable = True
    clock.now += 600  # within TTL
    sync.start()
    await sync.wait()
    assert sync.info()["stale"] is False


async def test_ensure_fresh_is_noop_within_ttl_and_while_running(
    fake: FakeUsom, sync: SyncManager, clock: Clock
) -> None:
    fake.rows = _rows(5)
    sync.start()
    await sync.wait()
    fake.calls.clear()
    clock.now += 60
    sync.ensure_fresh()
    assert not sync.running and fake.calls == []
    clock.now += 7200
    sync.ensure_fresh()
    assert sync.running
    task = sync._task
    sync.ensure_fresh()
    assert sync._task is task  # no second concurrent sync
    await sync.wait()


async def test_min_retry_interval_prevents_hammering(
    fake: FakeUsom, sync: SyncManager, clock: Clock
) -> None:
    sync.config.min_retry_seconds = 60
    fake.unreachable = True
    sync.ensure_fresh()
    await sync.wait()
    first = len(fake.calls)
    sync.ensure_fresh()
    assert not sync.running  # retried too soon
    clock.now += 61
    sync.ensure_fresh()
    assert sync.running
    await sync.wait()
    assert first == 0


async def test_interrupted_full_sync_resumes_from_checkpoint(
    fake: FakeUsom, sync: SyncManager, store: Store
) -> None:
    fake.rows = _rows(120)
    req = httpx.Request("GET", "https://x")

    def fail_page_three(request: httpx.Request) -> httpx.Response | None:
        if request.url.path == "/api/address/index" and request.url.params.get("page") == "3":
            raise httpx.ReadError("reset", request=req)
        return None

    fake.interceptor = fail_page_three
    sync.start()
    await sync.wait()
    assert sync.state() == "empty"  # nothing swapped in
    assert sync.staging_path.exists()
    fake.interceptor = None
    fake.calls.clear()
    sync.clock = lambda: (sync._last_attempt or 0) + 120
    sync.start()
    await sync.wait()
    assert store.count() == 120
    full_pages = [
        c["page"] for c in fake.calls if c.get("per-page") == "50" and "date_gte" not in c
    ]
    assert full_pages[0] == "3"  # resumed from the checkpoint, did not restart at page 1


async def test_incomplete_full_download_is_rejected(
    fake: FakeUsom, sync: SyncManager, store: Store
) -> None:
    fake.rows = _rows(100)
    real = fake.__call__

    def short_page_two(request: httpx.Request) -> httpx.Response | None:
        if request.url.path == "/api/address/index" and request.url.params.get("page") == "2":
            fake.interceptor = None
            body = real(request).json()
            body["models"] = body["models"][:5]  # upstream silently returns a short page
            fake.interceptor = short_page_two
            return httpx.Response(200, json=body)
        return None

    fake.interceptor = short_page_two
    sync.start()
    await sync.wait()
    assert sync.state() == "empty"
    assert "incomplete" in (sync.info()["last_error"] or "")


async def test_drift_triggers_full_resync_when_last_full_is_old(
    fake: FakeUsom, sync: SyncManager, store: Store, clock: Clock
) -> None:
    fake.rows = _rows(10)
    sync.start()
    await sync.wait()
    fake.rows = fake.rows[:8]  # upstream deleted two records
    clock.now += 2 * 86400  # beyond the drift recheck interval, below the 7-day full interval
    sync.start()
    await sync.wait()
    assert store.count() == 10 and sync.info()["drift"] == 2
    assert store.get_meta("needs_full") == "1"
    clock.now += 7200
    sync.start()
    await sync.wait()
    assert store.count() == 8 and sync.info()["drift"] == 0  # reconciled via full resync
    assert store.get_meta("needs_full") is None


async def test_weekly_full_resync(fake: FakeUsom, sync: SyncManager, clock: Clock) -> None:
    fake.rows = _rows(10)
    sync.start()
    await sync.wait()
    first_full = sync.info()["last_full_sync"]
    clock.now += 8 * 86400
    sync.start()
    await sync.wait()
    assert sync.info()["last_full_sync"] != first_full


async def test_dictionaries_are_loaded(fake: FakeUsom, sync: SyncManager, store: Store) -> None:
    fake.rows = _rows(3)
    sync.start()
    await sync.wait()
    assert store.dictionary("category")["BP"][0] == "Financial Phishing"
    assert store.dictionary("source")["IH"][0] == "REPORTING"


async def test_incremental_on_empty_cache_is_refused(sync: SyncManager) -> None:
    sync.store.init(wal=False)
    with pytest.raises(SyncRejectedError):
        await sync.incremental_sync()


async def test_auto_refresh_disabled_never_touches_network(
    fake: FakeUsom, sync: SyncManager
) -> None:
    sync.auto_refresh = False
    sync.ensure_fresh()
    assert not sync.running and fake.calls == []
    fake.rows = _rows(3)
    sync.start()  # explicit start still works (used by `usom-mcp --sync`)
    await sync.wait()
    assert sync.state() == "ready"


async def test_corrupt_cache_is_discarded_and_rebuilt(
    fake: FakeUsom, sync: SyncManager, store: Store
) -> None:
    store.path.write_bytes(b"garbage" * 500)
    assert sync.state() == "empty"  # a corrupt file must not crash status queries
    fake.rows = _rows(5)
    sync.start()
    await sync.wait()
    assert sync.state() == "ready" and store.count() == 5
    assert sync.info()["records"] == 5


async def test_full_sync_survives_upstream_shape_less_pages(
    fake: FakeUsom, sync: SyncManager, store: Store
) -> None:
    fake.rows = _rows(120)
    fake.interceptor = lambda r: (
        httpx.Response(200, json={"models": []})
        if r.url.params.get("per-page") == "50" and r.url.params.get("page") == "2"
        else None
    )
    sync.start()
    await sync.wait()
    assert sync.state() == "ready" and store.count() == 120
    assert sync.info()["last_error"] is None and sync.info()["drift"] == 0


async def test_stats_breakdown_follows_syncs(
    fake: FakeUsom, sync: SyncManager, store: Store, clock: Clock
) -> None:
    fake.rows = _rows(4)
    sync.start()
    await sync.wait()
    assert store.breakdown()["type"] == {"domain": 4}
    fake.rows += [make_row(50, "1.2.3.4", "ip", date="2026-10-02 08:00:00")]
    clock.now += 7200
    sync.start()
    await sync.wait()
    assert store.breakdown()["type"] == {"domain": 4, "ip": 1}
