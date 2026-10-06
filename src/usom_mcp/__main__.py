"""Command line entry point: ``usom-mcp`` / ``uvx usom-mcp``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Sequence

from . import __version__
from .config import Settings
from .server import App, create_server


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usom-mcp",
        description="MCP server for the USOM / SGB malicious address list.",
    )
    parser.add_argument("--version", action="version", version=f"usom-mcp {__version__}")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=os.environ.get("USOM_MCP_TRANSPORT", "stdio"),
        help="stdio (default) or streamable HTTP",
    )
    parser.add_argument("--host", default=os.environ.get("USOM_MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("USOM_MCP_PORT", "8000")))
    parser.add_argument("--path", default=os.environ.get("USOM_MCP_PATH", "/mcp"))
    parser.add_argument(
        "--sync",
        action="store_true",
        help="download/refresh the local cache, print a summary and exit (pre-warm)",
    )
    return parser


async def _sync_only(settings: Settings) -> int:
    app = App(settings)
    app.sync.start()
    await app.sync.wait()
    info = app.sync.info()
    await app.aclose()
    print(
        f"state={info['state']} records={info['records']} last_sync={info['last_sync']} "
        f"last_error={info['last_error']}"
    )
    return 1 if info["last_error"] and not info["records"] else 0


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    # stdout is the MCP channel on stdio: all logging goes to stderr.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    package_logger = logging.getLogger("usom_mcp")
    package_logger.handlers[:] = [handler]
    package_logger.propagate = False
    package_logger.setLevel(os.environ.get("USOM_MCP_LOG_LEVEL", "INFO").upper())
    settings = Settings()
    if args.sync:
        raise SystemExit(asyncio.run(_sync_only(settings)))
    server = create_server(settings)
    if args.transport == "http":
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            logging.getLogger("usom_mcp").warning(
                "binding to %s without authentication; the watch list is shared by every client",
                args.host,
            )
        server.run(
            transport="http", host=args.host, port=args.port, path=args.path, show_banner=False
        )
    else:
        server.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
