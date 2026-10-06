"""Runtime settings, overridable through environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import user_data_dir

from .api import DEFAULT_BASE_URL


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


@dataclass(frozen=True, slots=True)
class Settings:
    home: Path = field(
        default_factory=lambda: Path(os.environ.get("USOM_MCP_HOME") or user_data_dir("usom-mcp"))
    )
    base_url: str = field(
        default_factory=lambda: os.environ.get("USOM_MCP_BASE_URL", DEFAULT_BASE_URL)
    )
    ttl_seconds: float = field(default_factory=lambda: _float_env("USOM_MCP_TTL_SECONDS", 3600.0))
    #: set USOM_MCP_NO_SYNC=1 to never touch the network for cache refreshes (offline use)
    background_sync: bool = field(default_factory=lambda: os.environ.get("USOM_MCP_NO_SYNC") != "1")
    virustotal_key: str | None = field(
        default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY") or None
    )
    abuseipdb_key: str | None = field(
        default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY") or None
    )

    @property
    def cache_path(self) -> Path:
        return self.home / "cache.db"

    @property
    def watch_path(self) -> Path:
        return self.home / "watch.db"
