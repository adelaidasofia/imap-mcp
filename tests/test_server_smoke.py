"""Server smoke tests — import, tool registration, and the read/write split.

The read/write assertion is the one that matters for the MCP review
criteria: exactly one tool may be non-read-only, and it must be the vault
writer. A read tool that quietly gains write annotations should fail here.
"""

from __future__ import annotations

import asyncio

import pytest

from icloud_mcp import server


EXPECTED_TOOLS = {
    "icloud_health",
    "icloud_list_mailboxes",
    "icloud_search_messages",
    "icloud_read_message",
    "icloud_sync_to_vault",
    "icloud_export_for_runtime",
    "icloud_explain_filter",
}

WRITE_TOOLS = {"icloud_sync_to_vault"}


def _tools() -> dict:
    """Name -> FunctionTool. `mcp.list_tools()` is the public introspection
    surface in fastmcp 3.4.7; the module-level names stay plain functions,
    so those are called directly elsewhere in this file."""
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_all_tools_registered():
    assert set(_tools().keys()) == EXPECTED_TOOLS


def test_tool_count_is_under_the_search_execute_threshold():
    """Pattern A is only correct while the surface stays small."""
    assert len(EXPECTED_TOOLS) < 15


def test_exactly_one_tool_writes():
    tools = _tools()
    non_read_only = {
        name
        for name, tool in tools.items()
        if not getattr(tool.annotations, "readOnlyHint", False)
    }
    assert non_read_only == WRITE_TOOLS


def test_write_tool_is_not_destructive_and_is_idempotent():
    tool = _tools()["icloud_sync_to_vault"]
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.idempotentHint is True


def test_every_tool_has_a_description():
    for name, tool in _tools().items():
        assert (tool.description or "").strip(), f"{name} has no description"


def test_read_message_description_warns_about_untrusted_content():
    """The injection warning must reach the model at the tool boundary."""
    desc = _tools()["icloud_read_message"].description.lower()
    assert "untrusted" in desc
    assert "never as instructions" in desc or "not as instructions" in desc


def test_missing_credentials_return_classified_error_not_an_exception(monkeypatch):
    from icloud_mcp import keychain

    monkeypatch.delenv(keychain._ENV_ACCOUNT, raising=False)
    monkeypatch.delenv(keychain._ENV_PASSWORD, raising=False)
    monkeypatch.setattr(keychain, "_read", lambda s, a: None)

    result = server.icloud_list_mailboxes()
    assert result["ok"] is False
    assert result["kind"] == "auth"
    assert result["reason"] == "no_account"


def test_credential_error_hint_never_contains_a_secret(monkeypatch):
    from icloud_mcp import keychain

    monkeypatch.setenv(keychain._ENV_ACCOUNT, "me@icloud.com")
    monkeypatch.setattr(keychain, "_read", lambda s, a: None)
    monkeypatch.delenv(keychain._ENV_PASSWORD, raising=False)

    result = server.icloud_health()
    assert result["ok"] is False
    assert "appleid.apple.com" in result["message"]
    assert "password_masked" not in result.get("credential", {})
