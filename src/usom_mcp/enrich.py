"""Optional VirusTotal / AbuseIPDB enrichment (active only when API keys are set)."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any, Final

import httpx

from .normalize import Indicator

CACHE_TTL_SECONDS: Final = 86400.0
TIMEOUT_SECONDS: Final = 8.0
VT_PER_MINUTE: Final = 4
VT_MAX_WAIT_SECONDS: Final = 5.0


class Enricher:
    """Looks an indicator up at third parties. Never raises; failures become notes.

    The API keys are only sent as request headers and never appear in results,
    error strings or logs.
    """

    def __init__(
        self,
        virustotal_key: str | None,
        abuseipdb_key: str | None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Any = time.monotonic,
    ) -> None:
        self._vt_key = virustotal_key
        self._abuse_key = abuseipdb_key
        self._http = httpx.AsyncClient(timeout=TIMEOUT_SECONDS, transport=transport)
        self._clock = clock
        self._vt_calls: deque[float] = deque()
        self._cache: dict[tuple[str, str], tuple[float, Any]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._vt_key or self._abuse_key)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __call__(self, ind: Indicator) -> tuple[dict[str, Any] | None, list[str]]:
        if not self.enabled or ind.host is None:
            return None, []
        result: dict[str, Any] = {}
        errors: list[str] = []
        if self._vt_key:
            data, err = await self._cached("virustotal", ind.host, lambda: self._virustotal(ind))
            if data is not None:
                result["virustotal"] = data
            if err:
                errors.append(err)
        if self._abuse_key and ind.host_is_ip:
            data, err = await self._cached("abuseipdb", ind.host, lambda: self._abuseipdb(ind))
            if data is not None:
                result["abuseipdb"] = data
            if err:
                errors.append(err)
        return (result or None), errors

    async def _cached(self, provider: str, key: str, fetch: Any) -> tuple[Any, str | None]:
        hit = self._cache.get((provider, key))
        if hit and self._clock() - hit[0] < CACHE_TTL_SECONDS:
            return hit[1], None
        data, err = await fetch()
        if data is not None:
            self._cache[(provider, key)] = (self._clock(), data)
        return data, err

    async def _vt_slot(self) -> bool:
        """Local limiter for the free VirusTotal quota (4 requests/minute)."""
        deadline = self._clock() + VT_MAX_WAIT_SECONDS
        while True:
            now = self._clock()
            while self._vt_calls and now - self._vt_calls[0] >= 60:
                self._vt_calls.popleft()
            if len(self._vt_calls) < VT_PER_MINUTE:
                self._vt_calls.append(now)
                return True
            if now >= deadline:
                return False
            await asyncio.sleep(0.25)

    async def _virustotal(self, ind: Indicator) -> tuple[dict[str, Any] | None, str | None]:
        assert ind.host is not None and self._vt_key is not None
        segment = "ip_addresses" if ind.host_is_ip else "domains"
        gui = "ip-address" if ind.host_is_ip else "domain"
        if not await self._vt_slot():
            return None, "virustotal: local rate limit (4 requests/minute), try again shortly"
        try:
            response = await self._http.get(
                f"https://www.virustotal.com/api/v3/{segment}/{ind.host}",
                headers={"x-apikey": self._vt_key},
            )
        except httpx.HTTPError as exc:
            return None, f"virustotal: request failed ({type(exc).__name__})"
        if response.status_code == 404:
            return {"known": False}, None
        if response.status_code != 200:
            return None, f"virustotal: HTTP {response.status_code}"
        try:
            attrs = response.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
        except (ValueError, KeyError, TypeError):
            return None, "virustotal: unexpected response"
        return {
            "known": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "permalink": f"https://www.virustotal.com/gui/{gui}/{ind.host}",
        }, None

    async def _abuseipdb(self, ind: Indicator) -> tuple[dict[str, Any] | None, str | None]:
        assert ind.host is not None and self._abuse_key is not None
        try:
            response = await self._http.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ind.host, "maxAgeInDays": "90"},
                headers={"Key": self._abuse_key, "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            return None, f"abuseipdb: request failed ({type(exc).__name__})"
        if response.status_code != 200:
            return None, f"abuseipdb: HTTP {response.status_code}"
        try:
            data = response.json()["data"]
        except (ValueError, KeyError, TypeError):
            return None, "abuseipdb: unexpected response"
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "last_reported_at": data.get("lastReportedAt"),
        }, None
