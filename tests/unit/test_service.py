from __future__ import annotations

from typing import Any

import pytest

from tests.conftest import Clock, FakeUsom, make_row
from usom_mcp.service import parse_date_input


def types(result: Any) -> list[str]:
    return [m.match_type for m in result.matches]


async def test_domain_exact_hit_has_dates_source_and_labels(ready_app: Any) -> None:
    r = await ready_app.service.check_domain("EVIL.com")
    assert r.verdict == "listed" and r.normalized == "evil.com" and r.data_origin == "cache"
    m = r.matches[0]
    assert m.match_type == "exact" and m.usom_id == 1 and m.date == "2026-10-01 10:00:00"
    assert (m.category.id, m.category.en, m.category.tr) == (
        "BP",
        "Financial Phishing",
        "Bankacılık - Oltalama",
    )
    assert m.source.id == "SB" and m.criticality_level == 1
    assert r.source.startswith("T.C. Siber") and r.timestamps_timezone == "unspecified"
    assert r.stale is False and r.cache.state == "ready"


async def test_parent_listed_matches_subdomain_but_not_the_reverse(ready_app: Any) -> None:
    sub = await ready_app.service.check_domain("a.b.evil.com")
    assert sub.verdict == "listed" and types(sub) == ["subdomain"]
    # login.shop.example.org is listed; its parent shop.example.org is NOT
    parent = await ready_app.service.check_domain("shop.example.org")
    assert parent.verdict == "not_listed"
    assert "does not mean" in parent.note


async def test_www_variant_is_a_soft_match(ready_app: Any) -> None:
    r = await ready_app.service.check_domain("wonly.net")
    assert types(r) == ["www_variant"] and r.matches[0].listed_value == "www.wonly.net"


async def test_idn_input_matches_punycode_record(ready_app: Any) -> None:
    r = await ready_app.service.check_domain("bücher.de")
    assert r.verdict == "listed" and r.normalized == "xn--bcher-kva.de"


async def test_defanged_input(ready_app: Any) -> None:
    r = await ready_app.service.check_url("hxxps://evil[.]com/x")
    assert r.verdict == "listed"


async def test_url_exact_and_trailing_slash_tolerance(ready_app: Any) -> None:
    for u in ("http://bad.example/pay/now", "http://bad.example/pay/now/", "BAD.example/pay/now"):
        r = await ready_app.service.check_url(u)
        assert "url_exact" in types(r), u
    r = await ready_app.service.check_url("http://bad.example/promo")
    assert "url_exact" in types(r)  # listed with trailing slash


async def test_url_prefix_respects_path_boundaries(ready_app: Any) -> None:
    deep = await ready_app.service.check_url("http://bad.example/promo/summer?id=1")
    assert types(deep) == ["url_prefix"]
    lookalike = await ready_app.service.check_url("http://bad.example/promotion")
    assert lookalike.verdict == "not_listed"
    other = await ready_app.service.check_url("http://bad.example/safe")
    assert other.verdict == "not_listed"


async def test_url_prefix_boundary_without_trailing_slash(ready_app: Any) -> None:
    # listed: bad.example/pay/now (no trailing slash)
    child = await ready_app.service.check_url("http://bad.example/pay/now/step2")
    assert types(child) == ["url_prefix"]
    query = await ready_app.service.check_url("http://bad.example/pay/now?x=1")
    assert types(query) == ["url_prefix"]
    sibling = await ready_app.service.check_url("http://bad.example/pay/nowhere")
    assert sibling.verdict == "not_listed"


async def test_url_on_listed_domain_reports_subdomain_match(ready_app: Any) -> None:
    r = await ready_app.service.check_url("https://x.evil.com/anything")
    assert r.verdict == "listed" and types(r) == ["subdomain"]


async def test_url_with_ip_host_uses_ip_rules(ready_app: Any) -> None:
    r = await ready_app.service.check_url("http://203.0.113.7:8080/a")
    assert r.verdict == "listed" and types(r) == ["exact"]
    r2 = await ready_app.service.check_url("http://9.9.9.9/login")
    assert types(r2) == ["url_exact"]


async def test_ip_exact_cidr_and_ipv6_canonicalisation(ready_app: Any) -> None:
    assert types(await ready_app.service.check_ip("203.0.113.7")) == ["exact"]
    cidr = await ready_app.service.check_ip("198.51.100.200")
    assert types(cidr) == ["cidr"] and cidr.matches[0].listed_value == "198.51.100.0/24"
    assert (await ready_app.service.check_ip("198.51.101.1")).verdict == "not_listed"
    v6 = await ready_app.service.check_ip("2001:DB8::99")
    assert v6.verdict == "listed" and types(v6) == ["exact"]


@pytest.mark.parametrize(
    "call,value",
    [
        ("check_domain", ""),
        ("check_domain", "localhost"),
        ("check_domain", "1.2.3.4"),
        ("check_domain", "not a domain"),
        ("check_ip", "999.1.1.1"),
        ("check_ip", "evil.com"),
        ("check_ip", ""),
        ("check_url", ""),
        ("check_url", "ftp2://x"),
        ("check_url", "http://"),
        ("check_url", "x" * 5000),
    ],
)
async def test_invalid_input_returns_structured_error_not_exception(
    ready_app: Any, call: str, value: str
) -> None:
    r = await getattr(ready_app.service, call)(value)
    assert r.verdict == "unknown" and r.error is not None
    assert r.error.code == "invalid_input" and r.error.message
    assert len(r.input) <= 200


async def test_private_ip_gets_warning(ready_app: Any) -> None:
    r = await ready_app.service.check_ip("10.0.0.1")
    assert r.verdict == "not_listed" and r.warnings


async def test_stale_flag_when_refresh_fails_and_ttl_expired(
    ready_app: Any, fake: FakeUsom, clock: Clock
) -> None:
    fake.unreachable = True
    clock.now += 3 * 3600
    r = await ready_app.service.check_domain("evil.com")
    await ready_app.sync.wait()
    r = await ready_app.service.check_domain("evil.com")
    assert r.verdict == "listed" and r.data_origin == "cache"
    assert r.stale is True and r.cache.last_error


# -- live fallback while the cache is not ready --------------------------------------


@pytest.fixture
def cold_app(app: Any, fake: FakeUsom) -> Any:
    fake.rows = list(__import__("tests.conftest", fromlist=["SEED_ROWS"]).SEED_ROWS)
    app.sync.ensure_fresh = lambda: None  # keep the cache empty
    return app


async def test_live_fallback_domain_and_note(cold_app: Any) -> None:
    r = await cold_app.service.check_domain("a.evil.com")
    assert r.data_origin == "live" and r.cache.state == "empty"
    assert r.verdict == "listed" and types(r) == ["subdomain"]
    assert "live USOM API" in r.note


async def test_live_fallback_not_listed_and_ip_and_url(cold_app: Any) -> None:
    assert (await cold_app.service.check_domain("clean-site.org")).verdict == "not_listed"
    assert types(await cold_app.service.check_ip("203.0.113.7")) == ["exact"]
    url = await cold_app.service.check_url("http://bad.example/promo/x")
    assert "url_prefix" in types(url)


async def test_unknown_when_upstream_down_and_no_cache(cold_app: Any, fake: FakeUsom) -> None:
    fake.unreachable = True
    r = await cold_app.service.check_domain("evil.com")
    assert r.verdict == "unknown" and r.error and r.error.code == "upstream_unavailable"
    assert r.matches == []


# -- search / latest / stats ---------------------------------------------------------


async def test_latest_orders_newest_first_and_clamps(ready_app: Any) -> None:
    page = await ready_app.service.latest(limit=3)
    assert [i.usom_id for i in page.items] == [12, 11, 10]
    assert page.total_count == 12 and page.returned == 3
    assert (await ready_app.service.latest(limit=10_000)).returned == 12
    assert (await ready_app.service.latest(limit=0)).returned == 1


async def test_search_filters(ready_app: Any) -> None:
    s = ready_app.service
    assert (await s.search(query="WATCHED-CORP")).total_count == 2
    assert (await s.search(type="ip")).total_count == 1
    assert (await s.search(category="BP")).items[0].usom_id == 1
    assert (await s.search(source="US")).items[0].value == "203.0.113.7"
    assert (await s.search(max_criticality_level=1)).total_count == 1
    assert (await s.search(connection_type="MF")).items[0].usom_id == 4
    assert (await s.search(query="evil", offset=5)).returned == 0


async def test_search_date_to_is_inclusive_for_bare_dates(ready_app: Any) -> None:
    page = await ready_app.service.search(date_from="2026-10-06", date_to="2026-10-06")
    assert {i.usom_id for i in page.items} == {9, 10, 11, 12}
    assert (
        await ready_app.service.search(date_from="2026-10-06 10:00", date_to="2026-10-06 10:00:00")
    ).total_count == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"date_from": "yesterday"},
        {"date_to": "2026-13-45"},
        {"date_from": "2026-10-06", "date_to": "2026-10-01"},
        {"type": "bogus"},
        {"max_criticality_level": 0},
        {"max_criticality_level": 11},
    ],
)
async def test_search_invalid_input(ready_app: Any, kwargs: dict[str, Any]) -> None:
    page = await ready_app.service.search(**kwargs)
    assert page.error is not None and page.error.code == "invalid_input"
    assert page.items == [] and page.total_count == 0


async def test_search_live_fallback(cold_app: Any) -> None:
    page = await cold_app.service.search(query="evil", limit=5)
    assert page.data_origin == "live" and [i.value for i in page.items] == ["evil.com"]
    cold_app.client._client._transport  # noqa: B018 - ensure attribute exists for fake wiring


async def test_search_live_upstream_down(cold_app: Any, fake: FakeUsom) -> None:
    fake.unreachable = True
    page = await cold_app.service.search(query="x")
    assert page.error and page.error.code == "upstream_unavailable"


async def test_stats(ready_app: Any) -> None:
    st = await ready_app.service.stats()
    assert st.total_records == 12 and st.newest_record_date == "2026-10-06 11:30:00"
    assert st.by_type["domain"] == 6 and st.by_type["url"] == 3
    assert st.by_category["PH"] >= 1 and st.cache.state == "ready" and st.cache.drift == 0


async def test_stats_when_cache_empty(cold_app: Any) -> None:
    st = await cold_app.service.stats()
    assert st.total_records == 0 and st.cache.state == "empty" and st.by_type == {}


@pytest.mark.parametrize(
    ("text", "end", "expected"),
    [
        ("2026-10-06", False, "2026-10-06 00:00:00"),
        ("2026-10-06", True, "2026-10-06 23:59:59.999999"),
        ("2026-10-06 08:30", False, "2026-10-06 08:30:00"),
        ("2026-10-06T08:30:15", True, "2026-10-06 08:30:15"),
        ("2026-10-06 08:30", True, "2026-10-06 08:30:59.999999"),
    ],
)
def test_parse_date_input(text: str, end: bool, expected: str) -> None:
    assert parse_date_input(text, end_of_range=end) == expected


def test_make_row_helper_sanity() -> None:
    assert make_row(1, "a.com")["type"] == "domain"


async def test_overlong_filters_are_rejected(ready_app: Any) -> None:
    page = await ready_app.service.search(query="x" * 501)
    assert page.error and page.error.code == "invalid_input"
