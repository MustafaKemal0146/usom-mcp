"""Tests against the real SGB/USOM API. Opt in with ``USOM_LIVE=1 pytest -m live``.

They only read, make a handful of requests and never download the full list.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest

from usom_mcp.api import UsomClient
from usom_mcp.config import Settings
from usom_mcp.server import App
from usom_mcp.store import parse_row

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("USOM_LIVE") != "1", reason="set USOM_LIVE=1 to run"),
]


@pytest.fixture
async def live_client() -> AsyncIterator[UsomClient]:
    c = UsomClient()
    yield c
    await c.aclose()


async def test_type_totals_add_up_to_overall_total(live_client: UsomClient) -> None:
    total = (await live_client.list_addresses(per_page=1)).total_count
    parts = 0
    for t in ("domain", "url", "ip", "ip6", "ip6net"):
        parts += (await live_client.list_addresses(per_page=1, type=t)).total_count
    assert total > 100_000
    assert parts == total or abs(parts - total) <= 50  # list is live; tolerate concurrent edits


async def test_a_full_9999_page_parses_without_a_single_malformed_row(
    live_client: UsomClient,
) -> None:
    page = await live_client.list_addresses(page=1, per_page=9999)
    assert page.page_count >= 40 and len(page.rows) == 9999
    parsed = [parse_row(r) for r in page.rows]
    bad = [r for r, p in zip(page.rows, parsed, strict=True) if p is None]
    assert bad == []


async def test_pagination_quirks_still_hold(live_client: UsomClient) -> None:
    p0 = await live_client.list_addresses(page=0, per_page=3)
    p1 = await live_client.list_addresses(page=1, per_page=3)
    assert [r["id"] for r in p0.rows] == [r["id"] for r in p1.rows]  # request page is 1-based
    assert p1.page == 0  # response page is 0-based
    last = await live_client.list_addresses(page=p1.page_count, per_page=3)
    beyond = await live_client.list_addresses(page=p1.page_count + 5, per_page=3)
    assert [r["id"] for r in last.rows] == [r["id"] for r in beyond.rows]  # repeats last page


async def test_known_listed_domain_is_found_and_nonsense_is_not(
    live_client: UsomClient, tmp_path: Any
) -> None:
    app = App(Settings(home=tmp_path, background_sync=False), client=live_client)
    app.sync.ensure_fresh = lambda: None  # stay in live-fallback mode: no full download
    newest = await live_client.list_addresses(page=1, per_page=50, type="domain")
    target = parse_row(newest.rows[0])
    assert target is not None
    hit = await app.service.check_domain(target.value)
    assert hit.data_origin == "live" and hit.verdict == "listed"
    assert hit.matches[0].usom_id == target.id and hit.matches[0].date == target.date
    sub = await app.service.check_domain(f"x1.x2.{target.value}")
    assert sub.verdict == "listed" and sub.matches[0].match_type == "subdomain"
    miss = await app.service.check_domain("this-should-not-exist-zzq-90210.example")
    assert miss.verdict == "not_listed"


async def test_live_ip_and_url_checks(live_client: UsomClient, tmp_path: Any) -> None:
    app = App(Settings(home=tmp_path, background_sync=False), client=live_client)
    app.sync.ensure_fresh = lambda: None
    ips = await live_client.list_addresses(page=1, per_page=5, type="ip")
    ip = parse_row(ips.rows[0])
    assert ip is not None
    assert (await app.service.check_ip(ip.value)).verdict == "listed"
    urls = await live_client.list_addresses(page=1, per_page=5, type="url")
    u = parse_row(urls.rows[0])
    assert u is not None
    r = await app.service.check_url(f"https://{u.value}")
    assert r.verdict == "listed"


async def test_dictionaries_cover_codes_seen_in_data(live_client: UsomClient) -> None:
    page = await live_client.list_addresses(page=1, per_page=2000)
    seen = {r["desc"] for r in page.rows}
    known = {m["id"] for m in await live_client.get_dictionary("/api/address-description/index")}
    assert seen <= known, f"unknown category codes: {seen - known}"
