"""FastMCP server definition: tools, instructions and lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import httpx
from fastmcp import FastMCP
from pydantic import Field

from . import __version__
from .api import UsomClient
from .config import Settings
from .enrich import Enricher
from .models import (
    CheckResult,
    Stats,
    ThreatPage,
    ThreatType,
    WatchAddResult,
    WatchList,
    WatchRemoveResult,
    WatchReport,
)
from .service import Service
from .store import Store
from .sync import SyncConfig, SyncManager
from .watch import WatchService, WatchStore

INSTRUCTIONS = """\
Threat intelligence from the Turkish national malicious-address list (USOM / T.C. Siber \
Güvenlik Başkanlığı). Use check_url / check_domain / check_ip to test one indicator, \
search_threats / latest_threats to browse, stats for freshness, and watch_* to monitor \
your own domains and IPs. Always report the record date and source of a hit. If a result \
has stale=true or data_origin="live", tell the user the data may be incomplete. \
"not_listed" never proves that a target is safe.
"""

_READ_ONLY: dict[str, Any] = {"readOnlyHint": True, "openWorldHint": True}


class App:
    """Wires settings, cache, sync and services together."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: UsomClient | None = None,
        sync_config: SyncConfig | None = None,
        enricher_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.client = client or UsomClient(settings.base_url)
        self.store = Store(settings.cache_path)
        self.sync = SyncManager(
            self.store,
            self.client,
            sync_config or SyncConfig(ttl_seconds=settings.ttl_seconds),
            auto_refresh=settings.background_sync,
        )
        self.enricher = Enricher(
            settings.virustotal_key, settings.abuseipdb_key, transport=enricher_transport
        )
        self.service = Service(
            self.store,
            self.sync,
            self.client,
            enrich=self.enricher if self.enricher.enabled else None,
        )
        self.watch = WatchService(WatchStore(settings.watch_path), self.service)

    async def aclose(self) -> None:
        await self.sync.cancel()
        await self.client.aclose()
        await self.enricher.aclose()


def create_server(settings: Settings | None = None, *, app: App | None = None) -> FastMCP:
    app = app or App(settings or Settings())

    @asynccontextmanager
    async def lifespan(_: FastMCP) -> AsyncIterator[None]:
        app.settings.home.mkdir(parents=True, exist_ok=True)
        app.sync.ensure_fresh()  # no-op when background sync is disabled
        try:
            yield
        finally:
            await app.aclose()

    mcp = FastMCP(
        "usom-mcp",
        instructions=INSTRUCTIONS,
        version=__version__,
        lifespan=lifespan,
        mask_error_details=True,
    )
    svc, watch = app.service, app.watch

    @mcp.tool(annotations=_READ_ONLY)
    async def check_url(
        url: Annotated[str, Field(description="URL to check, e.g. https://example.com/login")],
        enrich: Annotated[
            bool, Field(description="Also query VirusTotal (needs VIRUSTOTAL_API_KEY).")
        ] = False,
    ) -> CheckResult:
        """Check whether a URL is listed by USOM (exact, parent-domain, URL path or CIDR match).

        Call this first when a user asks whether a link is safe. The result carries the
        match type, record date, source and category of every hit.
        """
        return await svc.check_url(url, enrich)

    @mcp.tool(annotations=_READ_ONLY)
    async def check_domain(
        domain: Annotated[str, Field(description="Domain such as login.example.com (IDN ok).")],
        enrich: Annotated[
            bool, Field(description="Also query VirusTotal (needs VIRUSTOTAL_API_KEY).")
        ] = False,
    ) -> CheckResult:
        """Check whether a domain is listed by USOM, including when a parent domain is listed."""
        return await svc.check_domain(domain, enrich)

    @mcp.tool(annotations=_READ_ONLY)
    async def check_ip(
        ip: Annotated[str, Field(description="IPv4 or IPv6 address.")],
        enrich: Annotated[
            bool,
            Field(description="Also query VirusTotal and AbuseIPDB (needs the matching API keys)."),
        ] = False,
    ) -> CheckResult:
        """Check whether an IP address is listed by USOM, exactly or inside a listed network."""
        return await svc.check_ip(ip, enrich)

    @mcp.tool(annotations=_READ_ONLY)
    async def latest_threats(
        limit: Annotated[int, Field(ge=1, le=200, description="How many records (1-200).")] = 20,
        type: Annotated[
            ThreatType | None, Field(description="Restrict to one indicator type.")
        ] = None,
        category: Annotated[
            str | None, Field(description="Category code: PH, BP, MD, MI, MU, MC or CA.")
        ] = None,
    ) -> ThreatPage:
        """Return the most recently added USOM records, newest first."""
        return await svc.latest(limit, type, category)

    @mcp.tool(annotations=_READ_ONLY)
    async def search_threats(
        query: Annotated[
            str | None, Field(description="Case-insensitive substring of the listed value.")
        ] = None,
        type: Annotated[ThreatType | None, Field(description="Indicator type.")] = None,
        category: Annotated[str | None, Field(description="Category code (PH, BP, ...).")] = None,
        source: Annotated[
            str | None, Field(description="Source code: US, SO, RS, IH or SB.")
        ] = None,
        connection_type: Annotated[
            str | None, Field(description="Connection type code (AC, BC, EK, MC, MF, MM, OT, PH).")
        ] = None,
        max_criticality_level: Annotated[
            int | None,
            Field(
                ge=1, le=10, description="Keep records at this level or more critical (1 = max)."
            ),
        ] = None,
        date_from: Annotated[
            str | None, Field(description="YYYY-MM-DD or YYYY-MM-DD HH:MM[:SS], inclusive.")
        ] = None,
        date_to: Annotated[
            str | None, Field(description="YYYY-MM-DD (whole day included) or with time.")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=200, description="Page size (1-200).")] = 50,
        offset: Annotated[int, Field(ge=0, description="Records to skip.")] = 0,
    ) -> ThreatPage:
        """Search the USOM list by keyword, type, category, source and date range."""
        return await svc.search(
            query=query,
            type=type,
            category=category,
            source=source,
            connection_type=connection_type,
            max_criticality_level=max_criticality_level,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            offset=offset,
        )

    @mcp.tool(annotations=_READ_ONLY)
    async def stats() -> Stats:
        """Report record counts, newest record date, last sync time and cache status."""
        return await svc.stats()

    @mcp.tool(annotations={"idempotentHint": True, "openWorldHint": False})
    async def watch_add(
        values: Annotated[
            list[str],
            Field(description="Domains, IPs, URLs or CIDR networks to monitor.", max_length=500),
        ],
        label: Annotated[
            str | None, Field(description="Optional note, e.g. the owning team.", max_length=200)
        ] = None,
    ) -> WatchAddResult:
        """Add your own domains/IPs/networks to the local watch list."""
        return await watch.add(values, label)

    @mcp.tool(annotations={"idempotentHint": True, "destructiveHint": True, "openWorldHint": False})
    async def watch_remove(
        values: Annotated[
            list[str], Field(description="Entries to remove from the watch list.", max_length=500)
        ],
    ) -> WatchRemoveResult:
        """Remove entries from the local watch list."""
        return await watch.remove(values)

    @mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
    async def watch_list() -> WatchList:
        """List everything on the local watch list."""
        return await watch.list_entries()

    @mcp.tool(annotations={"openWorldHint": True})
    async def watch_check(
        value: Annotated[
            str | None,
            Field(description="One watched entry; omit to scan the whole list in one call."),
        ] = None,
    ) -> WatchReport:
        """Scan the watch list against USOM. Domains also report listed subdomains below them.

        Each item shows what is new since the previous check.
        """
        return await watch.check(value)

    return mcp
