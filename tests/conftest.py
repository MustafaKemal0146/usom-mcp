"""Shared fixtures: a fake USOM server that reproduces the real API's quirks."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from usom_mcp.api import UsomClient
from usom_mcp.labels import CATEGORIES, CONNECTION_TYPES, SOURCES
from usom_mcp.store import Store
from usom_mcp.sync import SyncConfig, SyncManager


def make_row(
    id_: int,
    url: str,
    type_: str = "domain",
    *,
    desc: str = "PH",
    source: str = "IH",
    date: str = "2026-10-06 12:00:00",
    crit: int = 4,
    conn: str = "PH",
) -> dict[str, Any]:
    return {
        "id": id_,
        "url": url,
        "type": type_,
        "desc": desc,
        "source": source,
        "date": date,
        "criticality_level": crit,
        "connectiontype": conn,
    }


class FakeUsom:
    """Callable ``httpx`` mock handler emulating siberguvenlik.gov.tr/api quirks."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows: list[dict[str, Any]] = list(rows or [])
        self.calls: list[dict[str, str]] = []
        #: exceptions / responses consumed one per request before normal handling
        self.faults: list[Callable[[httpx.Request], httpx.Response] | Exception] = []
        self.unreachable = False
        #: optional hook; return a response to short-circuit normal handling
        self.interceptor: Callable[[httpx.Request], httpx.Response | None] | None = None

    def _dictionary(self, mapping: dict[str, tuple[str, str]]) -> httpx.Response:
        models = [{"id": k, "en_title": en, "tr_title": tr} for k, (en, tr) in mapping.items()]
        return httpx.Response(200, json={"totalCount": len(models), "models": models})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectError("unreachable", request=request)
        if self.faults:
            fault = self.faults.pop(0)
            if isinstance(fault, Exception):
                raise fault
            return fault(request)
        if self.interceptor is not None:
            override = self.interceptor(request)
            if override is not None:
                return override
        params = dict(request.url.params)
        self.calls.append({"path": request.url.path, **params})
        path = request.url.path
        if path == "/api/address-description/index":
            return self._dictionary(CATEGORIES)
        if path == "/api/address-connection-type/index":
            return self._dictionary(CONNECTION_TYPES)
        if path == "/api/address-source/index":
            return self._dictionary(SOURCES)
        if path != "/api/address/index":
            return httpx.Response(404)
        per_page = int(params.get("per-page", "20"))
        if per_page > 9999:
            return httpx.Response(429, text="<html>429 Too Many Requests</html>")
        per_page = max(1, per_page)

        def sort_key(r: Any) -> int:
            return r["id"] if isinstance(r, dict) and isinstance(r.get("id"), int) else -1

        rows = sorted(self.rows, key=sort_key, reverse=True)
        if "type" in params:
            if params["type"] not in {"domain", "url", "ip", "ip6", "ip6net"}:
                return httpx.Response(200, json={"models": [], "count": 0})  # shape-less, like prod
            rows = [r for r in rows if isinstance(r, dict) and r.get("type") == params["type"]]
        if "q" in params:
            rows = [
                r
                for r in rows
                if isinstance(r, dict) and params["q"].lower() in str(r.get("url", "")).lower()
            ]
        for key, field in (
            ("source", "source"),
            ("desc", "desc"),
            ("connectiontype", "connectiontype"),
        ):
            if key in params:
                rows = [r for r in rows if isinstance(r, dict) and r.get(field) == params[key]]
        if "date_gte" in params:
            rows = [
                r for r in rows if isinstance(r, dict) and str(r.get("date")) >= params["date_gte"]
            ]
        if "date_lte" in params:
            rows = [
                r for r in rows if isinstance(r, dict) and str(r.get("date")) <= params["date_lte"]
            ]
        page_count = math.ceil(len(rows) / per_page)
        page = max(1, int(params.get("page", "1")))
        page = min(page, max(page_count, 1))  # out-of-range pages repeat the last page
        chunk = rows[(page - 1) * per_page : page * per_page]
        return httpx.Response(
            200,
            json={
                "totalCount": len(rows),
                "count": len(chunk),
                "models": chunk,
                "page": page - 1,
                "pageCount": page_count,
            },
        )


@pytest.fixture
def fake() -> FakeUsom:
    return FakeUsom()


async def _no_sleep(_: float) -> None:
    return None


@pytest.fixture
def client(fake: FakeUsom) -> UsomClient:
    return UsomClient(
        "https://usom.test",
        transport=httpx.MockTransport(fake),
        backoff_base=0.0,
        sleep=_no_sleep,
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "cache.db")
    s.init(wal=False)
    return s


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def sync_config() -> SyncConfig:
    return SyncConfig(page_delay_seconds=0.0, min_retry_seconds=0.0, per_page=50)


@pytest.fixture
def sync(store: Store, client: UsomClient, clock: Clock, sync_config: SyncConfig) -> SyncManager:
    return SyncManager(store, client, sync_config, clock=clock, sleep=_no_sleep)


def dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


@pytest.fixture
def settings(tmp_path: Path) -> Any:
    from usom_mcp.config import Settings

    return Settings(home=tmp_path / "home", base_url="https://usom.test", background_sync=True)


@pytest.fixture
def app(settings: Any, client: UsomClient, clock: Clock, sync_config: SyncConfig) -> Any:
    from usom_mcp.server import App

    application = App(settings, client=client, sync_config=sync_config)
    application.sync.clock = clock
    application.sync.sleep = _no_sleep
    return application


SEED_ROWS: list[dict[str, Any]] = [
    make_row(1, "evil.com", date="2026-10-01 10:00:00", desc="BP", source="SB", crit=1),
    make_row(2, "login.shop.example.org", date="2026-10-02 10:00:00"),
    make_row(3, "www.wonly.net", date="2026-10-03 10:00:00"),
    make_row(4, "bad.example/pay/now", "url", date="2026-10-04 10:00:00", desc="MU", conn="MF"),
    make_row(5, "bad.example/promo/", "url", date="2026-10-04 11:00:00"),
    make_row(6, "203.0.113.7", "ip", date="2026-10-05 10:00:00", desc="MC", conn="BC", source="US"),
    make_row(7, "198.51.100.0/24", "ip6net", date="2026-10-05 11:00:00", desc="CA", conn="OT"),
    make_row(8, "2001:db8:0:0:0:0:0:99", "ip6", date="2026-10-05 12:00:00"),
    make_row(9, "xn--bcher-kva.de", date="2026-10-06 09:00:00"),
    make_row(10, "9.9.9.9/login", "url", date="2026-10-06 10:00:00"),
    make_row(11, "sub.watched-corp.com", date="2026-10-06 11:00:00"),
    make_row(12, "other.watched-corp.com", date="2026-10-06 11:30:00"),
]


@pytest.fixture
async def ready_app(app: Any, fake: FakeUsom) -> Any:
    fake.rows = list(SEED_ROWS)
    app.sync.start()
    await app.sync.wait()
    assert app.sync.state() == "ready"
    return app
