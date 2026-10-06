from __future__ import annotations

from typing import Any

import httpx
import pytest

from usom_mcp.enrich import Enricher
from usom_mcp.normalize import normalize_domain, normalize_ip


def _enricher(
    handler: Any, vt: str | None = "VT-SECRET", abuse: str | None = "AB-SECRET"
) -> Enricher:
    return Enricher(vt, abuse, transport=httpx.MockTransport(handler))


VT_BODY = {
    "data": {
        "attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60}, "reputation": -3}
    }
}
AB_BODY = {
    "data": {"abuseConfidenceScore": 88, "totalReports": 12, "countryCode": "RU", "isp": "X"}
}


def ok_handler(request: httpx.Request) -> httpx.Response:
    if "virustotal" in request.url.host:
        assert request.headers["x-apikey"] == "VT-SECRET"
        return httpx.Response(200, json=VT_BODY)
    assert request.headers["Key"] == "AB-SECRET"
    return httpx.Response(200, json=AB_BODY)


async def test_no_keys_is_silent_and_makes_no_requests() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    e = _enricher(boom, None, None)
    assert e.enabled is False
    assert await e(normalize_domain("evil.com")) == (None, [])


async def test_domain_uses_virustotal_only() -> None:
    data, errors = await _enricher(ok_handler)(normalize_domain("evil.com"))
    assert errors == [] and data is not None and set(data) == {"virustotal"}
    assert data["virustotal"]["malicious"] == 5
    assert data["virustotal"]["permalink"].endswith("/gui/domain/evil.com")


async def test_ip_uses_both_providers() -> None:
    data, _ = await _enricher(ok_handler)(normalize_ip("203.0.113.7"))
    assert data is not None and set(data) == {"virustotal", "abuseipdb"}
    assert data["abuseipdb"]["abuse_confidence_score"] == 88


async def test_only_one_key_configured() -> None:
    data, _ = await _enricher(ok_handler, vt=None)(normalize_ip("203.0.113.7"))
    assert data is not None and set(data) == {"abuseipdb"}


async def test_vt_404_means_unknown_not_error() -> None:
    data, errors = await _enricher(lambda r: httpx.Response(404))(normalize_domain("evil.com"))
    assert data == {"virustotal": {"known": False}} and errors == []


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401),
        httpx.Response(500),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={}),
    ],
)
async def test_failures_become_notes_without_leaking_the_key(response: httpx.Response) -> None:
    data, errors = await _enricher(lambda r: response)(normalize_domain("evil.com"))
    assert data is None and len(errors) == 1
    assert "SECRET" not in errors[0]


async def test_network_error_is_swallowed() -> None:
    def raise_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow", request=request)

    data, errors = await _enricher(raise_timeout)(normalize_domain("evil.com"))
    assert data is None and errors == ["virustotal: request failed (ConnectTimeout)"]


async def test_results_are_cached_per_provider_and_host() -> None:
    calls = 0

    def counting(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=VT_BODY)

    e = _enricher(counting)
    await e(normalize_domain("evil.com"))
    await e(normalize_domain("evil.com"))
    assert calls == 1
    await e(normalize_domain("other.com"))
    assert calls == 2


async def test_local_vt_rate_limit() -> None:
    now = [0.0]

    def clock() -> float:
        return now[0]

    e = Enricher(
        "k",
        None,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=VT_BODY)),
        clock=clock,
    )
    for i in range(4):
        data, errors = await e(normalize_domain(f"d{i}.example.com"))
        assert data and not errors
    now[0] = 10.0  # still inside the minute: 5th call waits, then gives up
    import asyncio

    original = asyncio.sleep

    async def fast_sleep(delay: float) -> None:
        now[0] += 3
        await original(0)

    asyncio.sleep = fast_sleep  # type: ignore[assignment]
    try:
        data, errors = await e(normalize_domain("d9.example.com"))
    finally:
        asyncio.sleep = original  # type: ignore[assignment]
    assert data is None and "rate limit" in errors[0]


async def test_service_enrich_is_opt_in_and_silent_without_keys(ready_app: Any) -> None:
    r = await ready_app.service.check_domain("evil.com", enrich=True)
    assert r.enrichment is None and r.enrichment_errors is None


async def test_service_enrich_with_keys(ready_app: Any) -> None:
    ready_app.service._enrich = _enricher(ok_handler)
    plain = await ready_app.service.check_domain("evil.com")
    assert plain.enrichment is None  # not requested
    r = await ready_app.service.check_domain("evil.com", enrich=True)
    assert r.enrichment and r.enrichment["virustotal"]["malicious"] == 5
    assert "VT-SECRET" not in r.model_dump_json()
