"""The write plane is a separate opt-in surface, not a widened read grant.

An IMAP app password already carries full read and write on the whole
account, so there is no scope to withhold the way an OAuth connector can.
The staged consent therefore lives at the tool layer: without
IMAP_MCP_ENABLE_WRITES the mailbox-write tools are never registered, so they
are absent from list_tools entirely.

Absence is a stronger property than a runtime permission check. A tool that
exists but refuses can still be argued with, retried, or reached by a path
nobody thought about; a tool that was never registered cannot be called at
all. The first two tests prove that in a clean interpreter rather than by
reading the code, because this module is imported once per session and the
rest of the suite deliberately turns the plane on.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from imap_mcp import server

REPO = Path(__file__).resolve().parent.parent

_LIST_TOOLS = textwrap.dedent(
    """
    import asyncio, json
    from imap_mcp import server
    print(json.dumps(sorted(t.name for t in asyncio.run(server.mcp.list_tools()))))
    """
)

MAILBOX_WRITE_TOOLS = {
    "imap_create_draft",
    "imap_update_draft",
    "imap_delete_messages",
    "imap_archive_messages",
    "imap_move_messages",
    "imap_mark_messages",
}


def _tools_in_a_fresh_process(**env_overrides) -> set[str]:
    env = {k: v for k, v in os.environ.items() if k != server.ENV_ENABLE_WRITES}
    env.update(env_overrides)
    proc = subprocess.run(
        [sys.executable, "-c", _LIST_TOOLS],
        cwd=REPO,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return set(json.loads(proc.stdout.strip().splitlines()[-1]))


def test_no_mailbox_write_tool_exists_by_default():
    """Install it and do nothing else: the server is read-only."""
    tools = _tools_in_a_fresh_process()
    assert tools & MAILBOX_WRITE_TOOLS == set()
    # ...and the read surface is untouched and complete.
    assert "imap_search_messages" in tools
    assert "imap_sync_to_vault" in tools
    assert len(tools) == 8


def test_opting_in_adds_exactly_the_write_tools():
    tools = _tools_in_a_fresh_process(IMAP_MCP_ENABLE_WRITES="1")
    assert MAILBOX_WRITE_TOOLS <= tools
    assert len(tools) == 14


def test_the_flag_is_read_strictly(monkeypatch):
    for value in ("1", "true", "TRUE", "yes", "on", " on "):
        monkeypatch.setenv(server.ENV_ENABLE_WRITES, value)
        assert server.write_plane_enabled() is True, value
    for value in ("", "0", "false", "no", "off", "maybe", "read-only"):
        monkeypatch.setenv(server.ENV_ENABLE_WRITES, value)
        assert server.write_plane_enabled() is False, value


def test_the_flag_defaults_to_off(monkeypatch):
    monkeypatch.delenv(server.ENV_ENABLE_WRITES, raising=False)
    assert server.write_plane_enabled() is False


def test_registration_is_idempotent():
    """Re-registering must not raise or duplicate."""
    first = server.register_write_tools()
    second = server.register_write_tools()
    assert first == second == sorted(MAILBOX_WRITE_TOOLS)


def test_the_provider_listing_says_whether_writes_are_on(monkeypatch):
    monkeypatch.delenv(server.ENV_ENABLE_WRITES, raising=False)
    disabled = server.imap_list_providers()["write_plane"]
    assert disabled.startswith("disabled")
    assert server.ENV_ENABLE_WRITES in disabled

    monkeypatch.setenv(server.ENV_ENABLE_WRITES, "1")
    assert server.imap_list_providers()["write_plane"] == "enabled"


def test_every_registered_write_tool_is_in_the_spec_table():
    """The table is the single source of truth for what gets registered."""
    assert set(server.MAILBOX_WRITE_TOOL_SPECS) == MAILBOX_WRITE_TOOLS
