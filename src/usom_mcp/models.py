"""Pydantic models returned by the MCP tools."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

DATA_SOURCE = "T.C. Siber Güvenlik Başkanlığı / USOM (siberguvenlik.gov.tr)"
TIMEZONE_NOTE = "unspecified"

MatchType = Literal["exact", "subdomain", "www_variant", "url_exact", "url_prefix", "cidr"]
ThreatType = Literal["domain", "url", "ip", "ip6", "ip6net"]


class Label(BaseModel):
    id: str
    en: str
    tr: str


class Match(BaseModel):
    match_type: MatchType
    listed_value: str = Field(description="The value as listed by USOM.")
    type: str
    category: Label
    connection_type: Label
    source: Label
    criticality_level: int = Field(description="1 = highest criticality, 10 = lowest.")
    date: str = Field(description="Record date as published by USOM (timezone unspecified).")
    usom_id: int


class SyncProgress(BaseModel):
    phase: str
    pages_done: int
    pages_total: int


class CacheInfo(BaseModel):
    state: Literal["empty", "building", "ready", "refreshing"]
    records: int
    last_sync: str | None = Field(description="UTC ISO timestamp of the last successful sync.")
    age_seconds: int | None
    ttl_seconds: int
    stale_severity: Literal["normal", "high"] | None = None
    last_error: str | None = None
    progress: SyncProgress | None = None
    remote_total: int | None = None
    drift: int | None = Field(None, description="Local record count minus upstream totalCount.")
    skipped_malformed: int = 0
    last_full_sync: str | None = None
    last_incremental_sync: str | None = None


class ErrorInfo(BaseModel):
    code: Literal["invalid_input", "upstream_unavailable"]
    message: str
    hint: str | None = None


class Envelope(BaseModel):
    stale: bool = Field(
        description="True when a refresh failed and cached data may be outdated; warn the user."
    )
    data_origin: Literal["cache", "live"]
    cache: CacheInfo
    source: str = DATA_SOURCE
    timestamps_timezone: str = TIMEZONE_NOTE


class CheckResult(Envelope):
    input: str
    kind: Literal["domain", "ip", "url"]
    normalized: str | None = None
    verdict: Literal["listed", "not_listed", "unknown"]
    matches: list[Match] = Field(default_factory=list)
    note: str = ""
    warnings: list[str] = Field(default_factory=list)
    error: ErrorInfo | None = None
    enrichment: dict[str, Any] | None = None
    enrichment_errors: list[str] | None = None


class ThreatItem(BaseModel):
    usom_id: int
    value: str
    type: str
    category: Label
    connection_type: Label
    source: Label
    criticality_level: int
    date: str


class ThreatPage(Envelope):
    total_count: int
    returned: int
    offset: int
    items: list[ThreatItem]
    note: str = ""
    error: ErrorInfo | None = None


class Stats(Envelope):
    total_records: int
    newest_record_date: str | None
    by_type: dict[str, int]
    by_category: dict[str, int]
    by_source: dict[str, int]


class WatchEntry(BaseModel):
    value: str
    kind: Literal["domain", "ip", "url", "network"]
    label: str | None = None
    added_at: str
    last_checked_at: str | None = None


class ErrorInfoWithValue(BaseModel):
    input: str
    code: Literal["invalid_input"] = "invalid_input"
    message: str
    hint: str | None = None


class WatchAddResult(BaseModel):
    added: list[WatchEntry]
    already_present: list[str]
    rejected: list[ErrorInfoWithValue]
    total: int


class WatchRemoveResult(BaseModel):
    removed: list[str]
    not_found: list[str]
    rejected: list[ErrorInfoWithValue]
    total: int


class WatchList(BaseModel):
    total: int
    entries: list[WatchEntry]


class WatchItemReport(BaseModel):
    value: str
    kind: Literal["domain", "ip", "url", "network"]
    label: str | None = None
    status: Literal["listed", "clean", "unknown"]
    matches: list[Match] = Field(default_factory=list)
    listed_below: list[Match] = Field(
        default_factory=list,
        description=(
            "Listed entries that are subdomains of a watched domain "
            "(or IPs inside a watched network)."
        ),
    )
    listed_below_total: int = 0
    new_since_last_check: list[int] = Field(
        default_factory=list, description="USOM ids not reported by the previous check."
    )
    warnings: list[str] = Field(default_factory=list)


class WatchReport(Envelope):
    checked: int
    listed: int
    clean: int
    unknown: int
    items: list[WatchItemReport]
    note: str = ""
    error: ErrorInfo | None = None
