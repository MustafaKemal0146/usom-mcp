from __future__ import annotations

from typing import Any

from tests.conftest import FakeUsom, make_row


async def test_add_normalizes_dedupes_and_rejects(ready_app: Any) -> None:
    w = ready_app.watch
    r = await w.add(
        [
            "WATCHED-corp.com",
            "https://watched-corp.com/",
            "203.0.113.7",
            "",
            "localhost",
            "10.0.0.0/8",
        ],
        "ops",
    )
    assert [e.value for e in r.added] == ["watched-corp.com", "203.0.113.7", "10.0.0.0/8"]
    assert [e.kind for e in r.added] == ["domain", "ip", "network"]
    assert r.already_present == ["watched-corp.com"]  # second form normalised to the same value
    assert len(r.rejected) == 2 and r.total == 3
    assert all(e.label == "ops" for e in r.added)


async def test_list_remove_and_empty_state(ready_app: Any) -> None:
    w = ready_app.watch
    assert (await w.list_entries()).total == 0
    empty = await w.check()
    assert empty.checked == 0 and "empty" in empty.note
    await w.add(["a-corp.com", "b-corp.com"])
    assert [e.value for e in (await w.list_entries()).entries] == ["a-corp.com", "b-corp.com"]
    r = await w.remove(["A-corp.com", "missing.com", "bad input"])
    assert r.removed == ["a-corp.com"] and r.not_found == ["missing.com"] and len(r.rejected) == 1
    assert r.total == 1


async def test_check_all_in_one_call_two_directions(ready_app: Any) -> None:
    w = ready_app.watch
    await w.add(
        ["watched-corp.com", "evil.com", "clean-corp.com", "203.0.113.7", "198.51.100.0/24"]
    )
    report = await w.check()
    assert (report.checked, report.listed, report.clean, report.unknown) == (5, 4, 1, 0)
    by = {i.value: i for i in report.items}
    corp = by["watched-corp.com"]
    # the domain itself is not listed, but two subdomains below it are
    assert corp.status == "listed" and corp.matches == [] and corp.listed_below_total == 2
    assert {m.listed_value for m in corp.listed_below} == {
        "sub.watched-corp.com",
        "other.watched-corp.com",
    }
    assert by["evil.com"].matches[0].match_type == "exact"
    assert by["clean-corp.com"].status == "clean"
    assert by["203.0.113.7"].status == "listed"
    net = by["198.51.100.0/24"]
    assert net.status == "listed" and net.listed_below[0].match_type == "cidr"
    assert report.data_origin == "cache" and report.stale is False


async def test_listed_below_excludes_lookalike_domains(ready_app: Any, fake: FakeUsom) -> None:
    fake.rows += [make_row(50, "notwatched-corp.com", date="2026-10-06 12:00:00")]
    ready_app.sync.clock.now += 7200
    ready_app.sync.start()
    await ready_app.sync.wait()
    await ready_app.watch.add(["watched-corp.com"])
    item = (await ready_app.watch.check()).items[0]
    assert item.listed_below_total == 2  # notwatched-corp.com is not a subdomain


async def test_new_since_last_check(ready_app: Any, fake: FakeUsom) -> None:
    w = ready_app.watch
    await w.add(["watched-corp.com"])
    first = (await w.check()).items[0]
    assert sorted(first.new_since_last_check) == [11, 12]  # never checked: everything is new
    second = (await w.check()).items[0]
    assert second.new_since_last_check == []
    fake.rows += [make_row(60, "third.watched-corp.com", date="2026-10-07 08:00:00")]
    ready_app.sync.clock.now += 7200
    ready_app.sync.start()
    await ready_app.sync.wait()
    third = (await w.check()).items[0]
    assert third.new_since_last_check == [60] and third.listed_below_total == 3
    assert (await w.list_entries()).entries[0].last_checked_at is not None


async def test_check_single_value_and_not_in_list(ready_app: Any) -> None:
    w = ready_app.watch
    await w.add(["evil.com", "clean-corp.com"])
    one = await w.check("EVIL.com")
    assert one.checked == 1 and one.items[0].value == "evil.com"
    missing = await w.check("other.com")
    assert missing.error and "not in the watch list" in missing.error.message
    bad = await w.check("not valid")
    assert bad.error and bad.error.code == "invalid_input"


async def test_watch_list_survives_cache_deletion(ready_app: Any) -> None:
    await ready_app.watch.add(["keep-me.com"])
    ready_app.store.path.unlink()
    assert [e.value for e in (await ready_app.watch.list_entries()).entries] == ["keep-me.com"]


async def test_watch_check_uses_live_fallback_and_marks_networks_unknown(
    app: Any, fake: FakeUsom
) -> None:
    from tests.conftest import SEED_ROWS

    fake.rows = list(SEED_ROWS)
    app.sync.ensure_fresh = lambda: None
    await app.watch.add(["watched-corp.com", "evil.com", "198.51.100.0/24"])
    report = await app.watch.check()
    by = {i.value: i for i in report.items}
    assert report.data_origin == "live"
    assert by["evil.com"].status == "listed" and by["watched-corp.com"].listed_below_total == 2
    assert by["198.51.100.0/24"].status == "unknown" and by["198.51.100.0/24"].warnings


async def test_watch_check_upstream_down_without_cache(app: Any, fake: FakeUsom) -> None:
    app.sync.ensure_fresh = lambda: None
    fake.unreachable = True
    await app.watch.add(["evil.com"])
    report = await app.watch.check()
    assert report.unknown == 1 and report.items[0].warnings


async def test_watch_list_size_cap(ready_app: Any, monkeypatch: Any) -> None:
    import usom_mcp.watch as watch_module

    monkeypatch.setattr(watch_module, "MAX_WATCH_ITEMS", 2)
    r = await ready_app.watch.add(["a1.com", "a2.com", "a3.com"])
    assert len(r.added) == 2 and "full" in r.rejected[0].message
