"""Async client for the SGB/USOM address API (https://siberguvenlik.gov.tr/api/).

Behaviours learned from the live service that this client guards against:

* ``page`` is 1-based in requests but 0-based in responses.
* A page beyond ``pageCount`` silently repeats the last page, so iteration is bounded
  by ``pageCount`` instead of "until empty".
* ``per-page`` above 9999 is rejected with HTTP 429, so it is always clamped.
* Connection resets and slow responses (3-14 s) are common; requests are retried.
* Unknown ``type`` values are not rejected upstream (they return an empty, shape-less
  body), so filters are validated here.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final

import httpx

from . import __version__

log = logging.getLogger("usom_mcp.api")

DEFAULT_BASE_URL: Final = "https://siberguvenlik.gov.tr"
MAX_PER_PAGE: Final = 9999
VALID_TYPES: Final = frozenset({"domain", "url", "ip", "ip6", "ip6net"})
USER_AGENT: Final = f"usom-mcp/{__version__} (+https://github.com/MustafaKemal0146/usom-mcp)"
_RETRY_STATUS: Final = frozenset({500, 502, 503, 504})
_MAX_PAGES: Final = 10_000


class UpstreamError(Exception):
    """The upstream API is unreachable or returned something unusable."""


class UpstreamShapeError(UpstreamError):
    """HTTP 200 whose body is not a list envelope (observed: ``{"models": []}`` for some pages).

    The same record range is usually served fine when requested in smaller slices, so
    bulk iteration falls back to splitting the page instead of failing the whole sync.
    """


@dataclass(frozen=True, slots=True)
class AddressPage:
    total_count: int
    page: int
    page_count: int
    rows: list[Any]


class UsomClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 60.0,
        max_retries: int = 4,
        backoff_base: float = 2.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=True,
        )
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET with retry on transport errors, 5xx and 429; returns decoded JSON."""
        last_error = "unknown error"
        for attempt in range(self._max_retries + 1):
            delay = self._backoff_base * (2**attempt)
            try:
                response = await self._client.get(path, params=params)
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                if response.status_code == 200:
                    try:
                        return response.json()
                    except ValueError as exc:
                        raise UpstreamError(
                            f"{path}: response is not JSON (content-type "
                            f"{response.headers.get('content-type')!r})"
                        ) from exc
                last_error = f"HTTP {response.status_code}"
                if response.status_code == 429:
                    retry_after = response.headers.get("retry-after", "")
                    delay = float(retry_after) if retry_after.isdigit() else delay * 2
                elif response.status_code not in _RETRY_STATUS:
                    raise UpstreamError(f"{path}: {last_error}")
            if attempt < self._max_retries:
                await self._sleep(delay + random.uniform(0, delay / 4))
        raise UpstreamError(
            f"{path}: giving up after {self._max_retries + 1} attempts ({last_error})"
        )

    async def list_addresses(
        self,
        *,
        page: int = 1,
        per_page: int = 100,
        q: str | None = None,
        type: str | None = None,
        date_gte: str | None = None,
        date_lte: str | None = None,
        source: str | None = None,
        desc: str | None = None,
        connectiontype: str | None = None,
        criticality_level: int | None = None,
    ) -> AddressPage:
        if type is not None and type not in VALID_TYPES:
            raise ValueError(f"invalid type {type!r}; expected one of {sorted(VALID_TYPES)}")
        params: dict[str, Any] = {
            "page": max(1, page),
            "per-page": min(max(1, per_page), MAX_PER_PAGE),
        }
        optional = {
            "q": q,
            "type": type,
            "date_gte": date_gte,
            "date_lte": date_lte,
            "source": source,
            "desc": desc,
            "connectiontype": connectiontype,
            "criticality_level": criticality_level,
        }
        params.update({k: v for k, v in optional.items() if v is not None})
        body = await self.get_json("/api/address/index", params)
        return _parse_page(body)

    async def list_addresses_split(
        self, *, page: int, per_page: int, **filters: Any
    ) -> AddressPage:
        """Like ``list_addresses`` but re-requests the same record range in smaller slices
        when upstream answers with a shape-less body."""
        try:
            return await self.list_addresses(page=page, per_page=per_page, **filters)
        except UpstreamShapeError as exc:
            divisor = next((d for d in range(2, per_page + 1) if per_page % d == 0), None)
            if divisor is None:  # per_page == 1: nothing left to split
                raise
            log.warning(
                "page %d (per-page %d) returned a bad body; retrying as %d slices: %s",
                page,
                per_page,
                divisor,
                exc,
            )
            size = per_page // divisor
            rows: list[Any] = []
            total = 0
            for sub in range((page - 1) * divisor + 1, page * divisor + 1):
                part = await self.list_addresses_split(page=sub, per_page=size, **filters)
                total = part.total_count
                rows.extend(part.rows)
            return AddressPage(
                total_count=total,
                page=page - 1,
                page_count=-(-total // per_page),
                rows=rows,
            )

    async def iter_pages(
        self, *, start_page: int = 1, per_page: int = MAX_PER_PAGE, **filters: Any
    ) -> AsyncIterator[AddressPage]:
        """Yield pages until ``pageCount`` is reached (never "until empty")."""
        page = start_page
        previous_first_id: Any = None
        while page <= _MAX_PAGES:
            result = await self.list_addresses_split(page=page, per_page=per_page, **filters)
            first_id = (
                result.rows[0].get("id")
                if result.rows and isinstance(result.rows[0], dict)
                else None
            )
            if page > start_page and first_id is not None and first_id == previous_first_id:
                return  # upstream repeated a page; stop instead of looping
            yield result
            if page >= result.page_count:
                return
            previous_first_id = first_id
            page += 1

    async def get_dictionary(self, path: str) -> list[dict[str, Any]]:
        body = await self.get_json(path)
        models = body.get("models") if isinstance(body, dict) else None
        if not isinstance(models, list):
            raise UpstreamError(f"{path}: unexpected dictionary shape")
        return [m for m in models if isinstance(m, dict) and isinstance(m.get("id"), str)]


def _parse_page(body: Any) -> AddressPage:
    if not isinstance(body, dict):
        raise UpstreamShapeError("unexpected response shape: not an object")
    total, models = body.get("totalCount"), body.get("models")
    if not isinstance(total, int) or not isinstance(models, list):
        raise UpstreamShapeError(
            f"unexpected response shape: missing totalCount/models (body: {str(body)[:120]})"
        )
    page, page_count = body.get("page", 0), body.get("pageCount", 0)
    if not isinstance(page, int) or not isinstance(page_count, int):
        raise UpstreamShapeError("unexpected response shape: bad page/pageCount")
    return AddressPage(total_count=total, page=page, page_count=page_count, rows=models)
