"""Lookup service: normalization + matching against the cache, with live fallback."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, Literal

from .api import UpstreamError, UsomClient
from .labels import DICTIONARY_KINDS
from .models import (
    CacheInfo,
    CheckResult,
    ErrorInfo,
    Label,
    Match,
    MatchType,
    Stats,
    ThreatItem,
    ThreatPage,
)
from .normalize import (
    Indicator,
    InvalidInputError,
    domain_candidates,
    normalize_domain,
    normalize_ip,
    normalize_url,
    url_value_candidates,
)
from .store import Store, Threat, parse_row
from .sync import SyncManager

_MATCH_ORDER: dict[str, int] = {
    "exact": 0,
    "url_exact": 0,
    "cidr": 1,
    "subdomain": 2,
    "url_prefix": 3,
    "www_variant": 4,
}
NOT_SAFE_NOTE = "Not found in the USOM list. This does not mean the target is safe."
LIVE_NOTE = (
    "Answered from the live USOM API because the local cache is not ready yet; "
    "CIDR range matching is skipped in this mode."
)
_DATE_INPUT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2})(?::(\d{2}))?)?$")
_MAX_FILTER_LENGTH = 500
_LIVE_PAGE = 100
_LIVE_MAX_PAGES = 3
EnrichHook = Callable[[Indicator], Awaitable[tuple[dict[str, Any] | None, list[str]]]]


def parse_date_input(text: str, *, end_of_range: bool) -> str:
    """Validate ``YYYY-MM-DD[ HH:MM[:SS]]`` and return the stored string form.

    Date-only upper bounds are widened to the end of that day, because the upstream
    API treats a bare date as 00:00:00 (so ``date_lte=2026-10-06`` would exclude the day).
    """
    match = _DATE_INPUT_RE.match(text.strip())
    if not match:
        raise InvalidInputError(f"invalid date {text!r}", "use YYYY-MM-DD or YYYY-MM-DD HH:MM[:SS]")
    day, hm, sec = match.groups()
    try:
        datetime.strptime(f"{day} {hm or '00:00'}", "%Y-%m-%d %H:%M")
    except ValueError as exc:
        raise InvalidInputError(f"invalid date {text!r}: {exc}") from exc
    if hm is None:
        return f"{day} 23:59:59.999999" if end_of_range else f"{day} 00:00:00"
    return f"{day} {hm}:{sec or ('59.999999' if end_of_range else '00')}"


class Service:
    def __init__(
        self,
        store: Store,
        sync: SyncManager,
        client: UsomClient,
        *,
        enrich: EnrichHook | None = None,
    ) -> None:
        self.store = store
        self.sync = sync
        self.client = client
        self._enrich = enrich
        self._labels: dict[str, dict[str, tuple[str, str]]] = {
            k: dict(v) for k, v in DICTIONARY_KINDS.items()
        }
        self._labels_loaded_at: str | None = None

    # -- common envelope --------------------------------------------------------------
    def cache_info(self) -> CacheInfo:
        info = self.sync.info()
        info.pop("stale", None)
        return CacheInfo(**info)

    def _envelope(self, origin: Literal["cache", "live"]) -> dict[str, Any]:
        info = self.sync.info()
        stale = info.pop("stale")
        return {"stale": stale, "data_origin": origin, "cache": CacheInfo(**info)}

    def cache_usable(self) -> bool:
        return self.sync.state() in ("ready", "refreshing")

    async def _refresh_labels(self) -> None:
        marker = self.store.get_meta("last_success") if self.store.path.exists() else None
        if marker == self._labels_loaded_at or not self.cache_usable():
            return
        for kind in DICTIONARY_KINDS:
            stored = await asyncio.to_thread(self.store.dictionary, kind)
            self._labels[kind].update(stored)
        self._labels_loaded_at = marker

    def label(self, kind: str, code: str) -> Label:
        en, tr = self._labels.get(kind, {}).get(code, (code, code))
        return Label(id=code, en=en, tr=tr)

    def to_match(self, t: Threat, match_type: MatchType) -> Match:
        return Match(
            match_type=match_type,
            listed_value=t.value,
            type=t.type,
            category=self.label("category", t.category),
            connection_type=self.label("connection_type", t.connection_type),
            source=self.label("source", t.source),
            criticality_level=t.criticality,
            date=t.date,
            usom_id=t.id,
        )

    def to_item(self, t: Threat) -> ThreatItem:
        return ThreatItem(
            usom_id=t.id,
            value=t.value,
            type=t.type,
            category=self.label("category", t.category),
            connection_type=self.label("connection_type", t.connection_type),
            source=self.label("source", t.source),
            criticality_level=t.criticality,
            date=t.date,
        )

    # -- finders (cache or live) ------------------------------------------------------
    async def _live_values(self, values: list[str]) -> list[Threat]:
        sem = asyncio.Semaphore(3)

        async def one(value: str) -> list[Threat]:
            found: list[Threat] = []
            async with sem:
                for page_no in range(1, _LIVE_MAX_PAGES + 1):
                    page = await self.client.list_addresses(
                        q=value, per_page=_LIVE_PAGE, page=page_no
                    )
                    for raw in page.rows:
                        t = parse_row(raw)
                        if t is not None and t.value == value:
                            found.append(t)
                    if page_no >= page.page_count:
                        break
            return found

        results = await asyncio.gather(*(one(v) for v in values))
        return [t for group in results for t in group]

    async def _find_values(self, values: list[str], *, live: bool) -> list[Threat]:
        if live:
            return await self._live_values(values)
        return await asyncio.to_thread(self.store.find_values, values)

    async def _find_url_rows(self, host: str, *, live: bool) -> list[Threat]:
        if not live:
            return await asyncio.to_thread(self.store.find_url_rows_for_host, host)
        page = await self.client.list_addresses(q=host, per_page=_LIVE_PAGE, type="url")
        rows = [parse_row(r) for r in page.rows]
        return [t for t in rows if t is not None and t.host == host and t.value != host]

    # -- check_* ----------------------------------------------------------------------
    def _result(
        self,
        raw: str,
        kind: Literal["domain", "ip", "url"],
        origin: Literal["cache", "live"],
        **fields: Any,
    ) -> CheckResult:
        return CheckResult(input=raw, kind=kind, **self._envelope(origin), **fields)

    async def _check(
        self,
        raw: str,
        kind: Literal["domain", "ip", "url"],
        normalizer: Callable[[object], Indicator],
        matcher: Callable[[Indicator, bool], Awaitable[list[Match]]],
        enrich: bool,
    ) -> CheckResult:
        self.sync.ensure_fresh()
        try:
            ind = normalizer(raw)
        except InvalidInputError as exc:
            return self._result(
                str(raw)[:200],
                kind,
                "cache" if self.cache_usable() else "live",
                verdict="unknown",
                error=ErrorInfo(code="invalid_input", message=str(exc), hint=exc.hint),
            )
        await self._refresh_labels()
        live = not self.cache_usable()
        origin: Literal["cache", "live"] = "live" if live else "cache"
        try:
            matches = await matcher(ind, live)
        except UpstreamError as exc:
            return self._result(
                raw,
                kind,
                origin,
                normalized=ind.value,
                verdict="unknown",
                warnings=list(ind.warnings),
                note="USOM data is unavailable and no local cache exists yet.",
                error=ErrorInfo(
                    code="upstream_unavailable",
                    message=str(exc),
                    hint="retry in a minute; the cache is built in the background",
                ),
            )
        matches.sort(key=lambda m: (_MATCH_ORDER[m.match_type], m.usom_id))
        note = "Listed in the USOM malicious address list." if matches else NOT_SAFE_NOTE
        if live:
            note = f"{note} {LIVE_NOTE}"
        result = self._result(
            raw,
            kind,
            origin,
            normalized=ind.value,
            verdict="listed" if matches else "not_listed",
            matches=matches,
            note=note,
            warnings=list(ind.warnings),
        )
        if enrich and self._enrich is not None:
            result.enrichment, errors = await self._enrich(ind)
            result.enrichment_errors = errors or None
        return result

    async def _match_domain(self, ind: Indicator, live: bool) -> list[Match]:
        assert ind.host is not None
        cmap = {c: mt for c, mt in reversed(domain_candidates(ind.host))}
        threats = await self._find_values(list(cmap), live=live)
        return [self.to_match(t, cmap[t.value]) for t in threats]  # type: ignore[arg-type]

    async def _match_ip(self, ind: Indicator, live: bool) -> list[Match]:
        assert ind.host is not None
        threats = await self._find_values([ind.host], live=live)
        matches = [self.to_match(t, "exact") for t in threats]
        if not live:
            ranges = await asyncio.to_thread(self.store.find_ip_in_ranges, ind.host)
            matches += [self.to_match(t, "cidr") for t in ranges]
        return matches

    async def _match_url(self, ind: Indicator, live: bool) -> list[Match]:
        assert ind.host is not None
        matches = await (
            self._match_ip(ind, live) if ind.host_is_ip else self._match_domain(ind, live)
        )
        if ind.path:
            exact = url_value_candidates(ind)
            for t in await self._find_values(exact, live=live):
                matches.append(self.to_match(t, "url_exact"))
            seen = {m.usom_id for m in matches}
            for t in await self._find_url_rows(ind.host, live=live):
                stored_path = t.value[len(ind.host) :]
                if t.id in seen or not stored_path.startswith("/"):
                    continue
                if _is_path_prefix(stored_path, ind.path):
                    matches.append(self.to_match(t, "url_prefix"))
        return matches

    async def check_domain(self, domain: str, enrich: bool = False) -> CheckResult:
        return await self._check(domain, "domain", normalize_domain, self._match_domain, enrich)

    async def check_ip(self, ip: str, enrich: bool = False) -> CheckResult:
        return await self._check(ip, "ip", normalize_ip, self._match_ip, enrich)

    async def check_url(self, url: str, enrich: bool = False) -> CheckResult:
        return await self._check(url, "url", normalize_url, self._match_url, enrich)

    # -- discovery --------------------------------------------------------------------
    async def latest(
        self,
        limit: int = 20,
        type: str | None = None,
        category: str | None = None,
    ) -> ThreatPage:
        return await self.search(type=type, category=category, limit=limit)

    async def search(
        self,
        *,
        query: str | None = None,
        type: str | None = None,
        category: str | None = None,
        source: str | None = None,
        connection_type: str | None = None,
        max_criticality_level: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ThreatPage:
        self.sync.ensure_fresh()
        live = not self.cache_usable()
        origin: Literal["cache", "live"] = "live" if live else "cache"

        def failure(
            code: Literal["invalid_input", "upstream_unavailable"],
            message: str,
            hint: str | None = None,
        ) -> ThreatPage:
            return ThreatPage(
                total_count=0,
                returned=0,
                offset=offset,
                items=[],
                error=ErrorInfo(code=code, message=message, hint=hint),
                **self._envelope(origin),
            )

        limit = min(max(1, limit), 200)
        offset = max(0, offset)
        valid_types = {"domain", "url", "ip", "ip6", "ip6net"}
        too_long = [
            name
            for name, value in (
                ("query", query),
                ("category", category),
                ("source", source),
                ("connection_type", connection_type),
            )
            if value is not None and len(value) > _MAX_FILTER_LENGTH
        ]
        if too_long:
            return failure("invalid_input", f"{', '.join(too_long)} is too long")
        if type is not None and type not in valid_types:
            return failure(
                "invalid_input", f"invalid type {type!r}", f"one of {sorted(valid_types)}"
            )
        if max_criticality_level is not None and not 1 <= max_criticality_level <= 10:
            return failure("invalid_input", "max_criticality_level must be between 1 and 10")
        try:
            gte = parse_date_input(date_from, end_of_range=False) if date_from else None
            lte = parse_date_input(date_to, end_of_range=True) if date_to else None
        except InvalidInputError as exc:
            return failure("invalid_input", str(exc), exc.hint)
        if gte and lte and gte > lte:
            return failure("invalid_input", "date_from is after date_to")
        await self._refresh_labels()
        q = query.strip().lower() if query else None
        if live:
            return await self._search_live(
                q, type, category, source, connection_type, max_criticality_level, gte, lte,
                limit, offset, failure,
            )  # fmt: skip
        total, rows = await asyncio.to_thread(
            self.store.search,
            query=q,
            type=type,
            category=category,
            source=source,
            connection_type=connection_type,
            max_criticality=max_criticality_level,
            date_from=gte,
            date_to=lte,
            limit=limit,
            offset=offset,
        )
        return ThreatPage(
            total_count=total,
            returned=len(rows),
            offset=offset,
            items=[self.to_item(t) for t in rows],
            **self._envelope(origin),
        )

    async def _search_live(
        self,
        q: str | None,
        type_: str | None,
        category: str | None,
        source: str | None,
        connection_type: str | None,
        max_crit: int | None,
        gte: str | None,
        lte: str | None,
        limit: int,
        offset: int,
        failure: Callable[..., ThreatPage],
    ) -> ThreatPage:
        try:
            page = await self.client.list_addresses(
                per_page=min(limit, _LIVE_PAGE * 2),
                q=q,
                type=type_,
                desc=category,
                source=source,
                connectiontype=connection_type,
                date_gte=gte[:19] if gte else None,
                date_lte=lte[:19] if lte else None,
            )
        except UpstreamError as exc:
            return failure("upstream_unavailable", str(exc), "retry in a minute")
        threats = [t for t in (parse_row(r) for r in page.rows) if t is not None]
        if max_crit is not None:
            threats = [t for t in threats if t.criticality <= max_crit]
        notes = (
            "Answered from the live API (local cache building): first page only, offset ignored."
        )
        return ThreatPage(
            total_count=page.total_count,
            returned=len(threats),
            offset=0,
            items=[self.to_item(t) for t in threats],
            note=notes,
            **self._envelope("live"),
        )

    async def stats(self) -> Stats:
        self.sync.ensure_fresh()
        usable = self.cache_usable()
        info = self.cache_info()
        if usable:
            breakdown = await asyncio.to_thread(self.store.breakdown)
            newest = await asyncio.to_thread(self.store.max_date)
        else:
            breakdown, newest = {"type": {}, "category": {}, "source": {}}, None
        return Stats(
            total_records=info.records,
            newest_record_date=newest,
            by_type=breakdown["type"],
            by_category=breakdown["category"],
            by_source=breakdown["source"],
            **self._envelope("cache"),
        )


def _is_path_prefix(stored: str, query: str) -> bool:
    """True if ``stored`` (a listed path) is a prefix of ``query`` on a path boundary."""
    if query == stored or query.rstrip("/") == stored.rstrip("/"):
        return True
    if not query.startswith(stored):
        return False
    return stored.endswith(("/", "?")) or query[len(stored)] in "/?"
