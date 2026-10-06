from __future__ import annotations

import httpx
import pytest

from tests.conftest import FakeUsom, make_row
from usom_mcp.api import UpstreamError, UsomClient


def _rows(n: int) -> list[dict]:
    return [make_row(i, f"d{i}.example.com") for i in range(1, n + 1)]


async def test_page_is_one_based_and_pagecount_bounds_iteration(
    fake: FakeUsom, client: UsomClient
) -> None:
    fake.rows = _rows(25)
    pages = [p async for p in client.iter_pages(per_page=10)]
    assert [len(p.rows) for p in pages] == [10, 10, 5]
    ids = [r["id"] for p in pages for r in p.rows]
    assert ids == sorted(set(ids), reverse=True) and len(ids) == 25
    assert [c["page"] for c in fake.calls] == ["1", "2", "3"]  # no page=4: bounded by pageCount


async def test_out_of_range_page_repeats_last_page_but_is_not_followed(
    fake: FakeUsom, client: UsomClient
) -> None:
    fake.rows = _rows(5)
    beyond = await client.list_addresses(page=99, per_page=10)
    assert len(beyond.rows) == 5  # the quirk is real in the fake, as in production
    pages = [p async for p in client.iter_pages(per_page=2)]
    assert sum(len(p.rows) for p in pages) == 5


async def test_iter_pages_stops_if_upstream_repeats_a_page(client: UsomClient) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = {
            "totalCount": 99,
            "count": 1,
            "models": [make_row(7, "a.example.com")],
            "page": 0,
            "pageCount": 50,
        }
        return httpx.Response(200, json=body)

    c = UsomClient("https://x.test", transport=httpx.MockTransport(handler), backoff_base=0)
    pages = [p async for p in c.iter_pages(per_page=1)]
    assert len(pages) == 1 and calls == 2  # second identical page detected, loop ended


async def test_per_page_is_clamped_never_triggers_cap_429(
    fake: FakeUsom, client: UsomClient
) -> None:
    fake.rows = _rows(3)
    await client.list_addresses(per_page=10_000)
    await client.list_addresses(per_page=0)
    assert [c["per-page"] for c in fake.calls] == ["9999", "1"]


async def test_retries_connection_reset_then_succeeds(fake: FakeUsom, client: UsomClient) -> None:
    fake.rows = _rows(2)
    req = httpx.Request("GET", "https://x")
    fake.faults = [httpx.ReadError("Connection reset by peer", request=req)] * 3
    page = await client.list_addresses()
    assert page.total_count == 2


async def test_gives_up_after_max_retries(fake: FakeUsom, client: UsomClient) -> None:
    fake.unreachable = True
    with pytest.raises(UpstreamError, match="giving up"):
        await client.list_addresses()


async def test_429_and_5xx_are_retried(fake: FakeUsom, client: UsomClient) -> None:
    fake.rows = _rows(1)
    fake.faults = [lambda r: httpx.Response(429), lambda r: httpx.Response(503)]
    assert (await client.list_addresses()).total_count == 1


async def test_non_retryable_4xx_fails_fast(client: UsomClient, fake: FakeUsom) -> None:
    fake.faults = [lambda r: httpx.Response(404)]
    with pytest.raises(UpstreamError, match="404"):
        await client.list_addresses()
    assert fake.faults == []  # exactly one attempt


async def test_html_body_is_rejected(client: UsomClient, fake: FakeUsom) -> None:
    fake.faults = [lambda r: httpx.Response(200, text="<html>maintenance</html>")]
    with pytest.raises(UpstreamError, match="not JSON"):
        await client.list_addresses()


@pytest.mark.parametrize(
    "body", [[], {"models": []}, {"totalCount": "x", "models": []}, {"totalCount": 1}]
)
async def test_unexpected_shapes_are_rejected(
    client: UsomClient, fake: FakeUsom, body: object
) -> None:
    fake.faults = [lambda r: httpx.Response(200, json=body)]
    with pytest.raises(UpstreamError, match="shape"):
        await client.list_addresses()


async def test_invalid_type_is_rejected_client_side(client: UsomClient) -> None:
    with pytest.raises(ValueError, match="invalid type"):
        await client.list_addresses(type="bogus")


async def test_dictionary_shape(client: UsomClient) -> None:
    models = await client.get_dictionary("/api/address-description/index")
    assert {m["id"] for m in models} >= {"PH", "BP"}


async def test_shape_less_page_is_refetched_in_smaller_slices(fake: FakeUsom) -> None:
    """Reproduces production: page 2 at per-page=50 answers ``{"models": []}`` but the same
    record range is fine when requested as 25-row slices."""
    fake.rows = _rows(120)
    real = fake.__call__

    def broken_page_two(request: httpx.Request) -> httpx.Response | None:
        p = request.url.params
        if p.get("per-page") == "50" and p.get("page") == "2":
            return httpx.Response(200, json={"models": []})
        return None

    fake.interceptor = broken_page_two
    c = UsomClient("https://usom.test", transport=httpx.MockTransport(real), backoff_base=0)
    pages = [p async for p in c.iter_pages(per_page=50)]
    ids = [r["id"] for p in pages for r in p.rows]
    assert len(ids) == 120 and len(set(ids)) == 120
    assert ids == sorted(ids, reverse=True)  # order preserved across the split
    assert [p.page_count for p in pages] == [3, 3, 3]


async def test_split_recurses_and_gives_up_at_single_rows(
    fake: FakeUsom, client: UsomClient
) -> None:
    fake.rows = _rows(9)

    def always_bad(request: httpx.Request) -> httpx.Response | None:
        if request.url.params.get("per-page") in {"9", "3", "1"}:
            return httpx.Response(200, json={"models": []})
        return None

    fake.interceptor = always_bad
    with pytest.raises(UpstreamError, match="shape"):
        await client.list_addresses_split(page=1, per_page=9)


async def test_split_uses_exact_row_ranges(fake: FakeUsom, client: UsomClient) -> None:
    fake.rows = _rows(12)
    fake.interceptor = lambda r: (
        httpx.Response(200, json={"models": []}) if r.url.params.get("per-page") == "6" else None
    )
    page = await client.list_addresses_split(page=2, per_page=6)  # rows 7..12 by position
    expected = [r["id"] for r in sorted(fake.rows, key=lambda r: r["id"], reverse=True)][6:12]
    assert [r["id"] for r in page.rows] == expected
    assert page.page == 1 and page.page_count == 2
