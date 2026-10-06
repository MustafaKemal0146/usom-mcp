"""Protocol-level tests: the tools exactly as an MCP client sees them."""

from __future__ import annotations

from typing import Any

import pytest
from fastmcp import Client

from usom_mcp.server import create_server

EXPECTED_TOOLS = {
    "check_url",
    "check_domain",
    "check_ip",
    "latest_threats",
    "search_threats",
    "stats",
    "watch_add",
    "watch_remove",
    "watch_list",
    "watch_check",
}


@pytest.fixture
async def client_session(ready_app: Any) -> Any:
    server = create_server(app=ready_app)
    async with Client(server) as c:
        yield c


async def test_tool_list_and_schemas(client_session: Client) -> None:
    tools = {t.name: t for t in await client_session.list_tools()}
    assert set(tools) == EXPECTED_TOOLS
    check_url = tools["check_url"]
    assert check_url.input_schema["required"] == ["url"]
    assert check_url.description and "safe" in check_url.description
    assert tools["check_url"].annotations and tools["check_url"].annotations.read_only_hint is True
    props = tools["search_threats"].input_schema["properties"]
    assert set(props) >= {"query", "type", "category", "date_from", "date_to", "limit", "offset"}
    assert tools["latest_threats"].input_schema["properties"]["limit"]["maximum"] == 200


async def test_check_domain_over_protocol(client_session: Client) -> None:
    res = await client_session.call_tool("check_domain", {"domain": "x.evil.com"})
    data = res.structured_content
    assert data["verdict"] == "listed" and data["matches"][0]["match_type"] == "subdomain"
    assert data["stale"] is False and data["cache"]["state"] == "ready"


async def test_invalid_input_is_not_a_protocol_error(client_session: Client) -> None:
    res = await client_session.call_tool("check_ip", {"ip": "999.1.1.1"})
    assert res.is_error is False
    assert res.structured_content["error"]["code"] == "invalid_input"


async def test_schema_violations_are_rejected_by_the_framework(client_session: Client) -> None:
    from fastmcp.exceptions import ToolError

    with pytest.raises(ToolError):
        await client_session.call_tool("latest_threats", {"limit": 5000})
    with pytest.raises(ToolError):
        await client_session.call_tool("check_url", {})
    with pytest.raises(ToolError):
        await client_session.call_tool("search_threats", {"type": "bogus"})


async def test_full_watch_flow_over_protocol(client_session: Client) -> None:
    c = client_session
    add = (
        await c.call_tool("watch_add", {"values": ["watched-corp.com", "evil.com"], "label": "t"})
    ).structured_content
    assert [e["value"] for e in add["added"]] == ["watched-corp.com", "evil.com"]
    assert (await c.call_tool("watch_list", {})).structured_content["total"] == 2
    report = (await c.call_tool("watch_check", {})).structured_content
    assert report["checked"] == 2 and report["listed"] == 2
    single = (await c.call_tool("watch_check", {"value": "evil.com"})).structured_content
    assert single["checked"] == 1
    rm = (await c.call_tool("watch_remove", {"values": ["evil.com"]})).structured_content
    assert rm["removed"] == ["evil.com"] and rm["total"] == 1


async def test_discovery_tools_over_protocol(client_session: Client) -> None:
    latest = (await client_session.call_tool("latest_threats", {"limit": 2})).structured_content
    assert [i["usom_id"] for i in latest["items"]] == [12, 11]
    found = (
        await client_session.call_tool("search_threats", {"query": "evil", "type": "domain"})
    ).structured_content
    assert found["total_count"] == 1
    st = (await client_session.call_tool("stats", {})).structured_content
    assert st["total_records"] == 12 and st["cache"]["records"] == 12


async def test_unexpected_exception_does_not_leak_details(ready_app: Any, monkeypatch: Any) -> None:
    from fastmcp.exceptions import ToolError

    async def boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("secret internal path /root/x")

    monkeypatch.setattr(ready_app.service, "check_domain", boom)
    async with Client(create_server(app=ready_app)) as c:
        with pytest.raises(ToolError) as exc:
            await c.call_tool("check_domain", {"domain": "evil.com"})
    assert "secret internal path" not in str(exc.value)
