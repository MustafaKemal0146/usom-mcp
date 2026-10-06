"""Keep README / SKILL.md honest: configs must parse and referenced tools must exist."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fastmcp import Client

from usom_mcp.server import create_server

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text(encoding="utf-8")
SKILL = (ROOT / "SKILL.md").read_text(encoding="utf-8")


def test_readme_json_snippets_are_valid_client_configs() -> None:
    blocks = re.findall(r"```json\n(.*?)\n```", README, flags=re.S)
    assert len(blocks) >= 4  # 2 languages x (Claude Desktop, Cursor)
    for block in blocks:
        config = json.loads(block)
        server = config["mcpServers"]["usom"]
        assert server["command"] == "uvx" and server["args"] == ["usom-mcp"]


def test_readme_is_bilingual_and_documents_every_client() -> None:
    headings = re.findall(r"^## (.+)$", README, flags=re.M)
    assert any(h.endswith("English") for h in headings)
    assert any(h.endswith("Türkçe") for h in headings)
    for needle in ("Claude Desktop", "Claude Code", "Cursor", "claude mcp add usom"):
        assert README.count(needle) >= 2, needle


def test_skill_has_frontmatter_and_is_short() -> None:
    match = re.match(r"^---\nname: (.+)\ndescription: (.+)\n---\n", SKILL)
    assert match and match.group(1) == "usom-mcp" and len(match.group(2)) > 40
    assert len(SKILL.splitlines()) < 60  # "short, command oriented"
    assert SKILL.isascii() or "→" in SKILL  # English only (arrows are the sole non-ASCII)


async def test_every_tool_mentioned_in_docs_exists(ready_app: Any) -> None:
    async with Client(create_server(app=ready_app)) as c:
        tools = {t.name for t in await c.list_tools()}
    mentioned = set(
        re.findall(r"`((?:check|watch|latest|search)_[a-z_]+|stats)(?:\(|`)", README + SKILL)
    )
    assert mentioned and mentioned <= tools, mentioned - tools
    # and every tool is documented
    assert all(t in README for t in tools), [t for t in tools if t not in README]
    assert all(t in SKILL for t in tools if t not in {"watch_remove", "watch_list"}), tools
