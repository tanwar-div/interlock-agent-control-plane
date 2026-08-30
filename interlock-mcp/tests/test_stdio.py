"""End-to-end protocol test.

The other tests call the handlers directly, which proves the logic. This one
spawns the server as a subprocess and talks to it as a real MCP client would,
which proves the thing an editor will actually do: that the process starts, the
handshake completes, and stdout carries nothing but protocol.

That last part is easy to break and hard to notice — a single stray `print` in
any imported module corrupts the stream, and the client sees a malformed message
rather than a crash.
"""
from __future__ import annotations

import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PARAMS = StdioServerParameters(
    command=sys.executable,
    args=["-m", "interlock_mcp"],
    env={
        **os.environ,
        "INTERLOCK_MCP_OFFLINE": "1",
        "INTERLOCK_PROJECT_ID": "",
        "INTERLOCK_MODEL_ARMOR_ENABLED": "false",
    },
)


@pytest.mark.asyncio
async def test_a_real_client_can_complete_a_session():
    async with stdio_client(PARAMS) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "interlock"
        # All three primitives, not just tools.
        assert init.capabilities.tools
        assert init.capabilities.resources
        assert init.capabilities.prompts
        # Instructions tell the calling model when to reach for this at all.
        assert init.instructions and "before you take it" in init.instructions

        names = {t.name for t in (await session.list_tools()).tools}
        assert names == {"score_action", "check_plan", "inspect_content"}

        result = await session.call_tool(
            "score_action",
            {"action_type": "sql.instances.delete",
             "parameters": {"instance": "prod-orders-db"}},
        )
        assert not result.is_error
        assert result.structured_content["decision"] == "DENY"

        body = (await session.read_resource("interlock://catalogue")).contents[0].text
        assert "sql.instances.delete" in body

        prompt = await session.get_prompt("before_you_act")
        assert "binding" in prompt.messages[0].content.text


@pytest.mark.asyncio
async def test_the_server_starts_with_no_configuration_at_all():
    """No project, no credentials, no network — and still a correct verdict.
    This is the claim the README makes, so it is the claim under test."""
    bare = StdioServerParameters(
        command=sys.executable,
        args=["-m", "interlock_mcp"],
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "INTERLOCK_MCP_OFFLINE": "1",
        },
    )
    async with stdio_client(bare) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool(
            "score_action",
            {"action_type": "storage.buckets.setIamPolicy",
             "parameters": {"bucket": "b", "member": "allUsers", "role": "roles/storage.admin"}},
        )
        assert result.structured_content["decision"] == "DENY"
        assert result.structured_content["severity"] == "CATASTROPHIC"
