"""Server smoke tests — import, tool registration, and the read/write split.

The read/write assertion is the one that matters for the MCP review
criteria. It changed in v0.3.0 and the change was deliberate, so it is worth
recording why rather than just widening a set.

Through v0.2.0 exactly ONE tool was non-read-only: the vault writer. Nothing
could touch a mailbox at all. v0.3.0 adds the mailbox write plane — drafts
and mailbox management — so the assertion is no longer "exactly one writer".
Weakening it to a bare count would have thrown away everything the test was
protecting, so it is now stricter in the direction that still matters:

* the READ set is pinned exactly, so a read tool that quietly gains write
  annotations still fails here — that was always the real point;
* every writer is named, and named in the right category;
* `destructiveHint` is asserted per tool against what the tool actually
  does, so an honest annotation cannot drift into a convenient one.
"""

from __future__ import annotations

import asyncio

import pytest

from imap_mcp import server


# Read-only: cannot change the mailbox OR the vault.
READ_TOOLS = {
    "imap_list_providers",
    "imap_health",
    "imap_list_mailboxes",
    "imap_search_messages",
    "imap_read_message",
    "imap_export_for_runtime",
    "imap_explain_filter",
}

# Writes notes into the second brain. Never touches the mailbox.
VAULT_WRITE_TOOLS = {"imap_sync_to_vault"}

# Changes the mailbox itself. Every one of these routes through write.py.
MAILBOX_WRITE_TOOLS = {
    "imap_create_draft",
    "imap_update_draft",
    "imap_delete_messages",
    "imap_archive_messages",
    "imap_move_messages",
    "imap_mark_messages",
}

# Mail ends up somewhere other than where it was. Recoverable — it is moved,
# never expunged — but a client showing a destructive-action warning should
# show one, so the hint says true.
DESTRUCTIVE_TOOLS = {
    "imap_delete_messages",
    "imap_archive_messages",
    "imap_move_messages",
    # Appends the new version, then moves the old one to Trash: IMAP has no
    # edit-in-place, so updating a draft genuinely moves mail.
    "imap_update_draft",
}

EXPECTED_TOOLS = READ_TOOLS | VAULT_WRITE_TOOLS | MAILBOX_WRITE_TOOLS


def _tools() -> dict:
    """Name -> FunctionTool. `mcp.list_tools()` is the public introspection
    surface in fastmcp 3.4.7; the module-level names stay plain functions,
    so those are called directly elsewhere in this file."""
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_all_tools_registered():
    assert set(_tools().keys()) == EXPECTED_TOOLS


def test_unconfigured_generic_provider_fails_loud_not_silently(monkeypatch):
    """A generic profile with no host must refuse, never fall back to some
    other operator's mail server."""
    monkeypatch.setenv(server.ENV_PROVIDER, "generic")
    monkeypatch.delenv(server.ENV_HOST, raising=False)
    result = server.imap_list_mailboxes()
    assert result["ok"] is False
    assert result["kind"] == "schema"
    assert "IMAP_HOST" in result["message"]


def test_unknown_provider_is_rejected(monkeypatch):
    monkeypatch.setenv(server.ENV_PROVIDER, "yahoo-typo")
    result = server.imap_list_mailboxes()
    assert result["ok"] is False
    assert "unknown provider" in result["message"]


def test_tool_count_is_under_the_search_execute_threshold():
    """Pattern A is only correct while the surface stays small."""
    assert len(EXPECTED_TOOLS) < 15


def test_the_read_only_set_is_exactly_pinned():
    """The assertion that survived v0.3.0: a read tool must stay read-only."""
    tools = _tools()
    read_only = {
        name
        for name, tool in tools.items()
        if getattr(tool.annotations, "readOnlyHint", False)
    }
    assert read_only == READ_TOOLS


def test_every_writer_is_named_and_categorised():
    tools = _tools()
    non_read_only = {
        name
        for name, tool in tools.items()
        if not getattr(tool.annotations, "readOnlyHint", False)
    }
    assert non_read_only == VAULT_WRITE_TOOLS | MAILBOX_WRITE_TOOLS


def test_destructive_hints_are_honest():
    """Asserted per tool against what it does, not against convenience."""
    tools = _tools()
    marked = {
        name
        for name, tool in tools.items()
        if getattr(tool.annotations, "destructiveHint", False)
    }
    assert marked == DESTRUCTIVE_TOOLS


def test_the_vault_writer_never_became_a_mailbox_writer():
    tool = _tools()["imap_sync_to_vault"]
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.idempotentHint is True


def test_flag_changes_are_idempotent_and_drafts_are_not():
    """Marking read twice is the same as once; drafting twice is two drafts."""
    tools = _tools()
    assert tools["imap_mark_messages"].annotations.idempotentHint is True
    assert tools["imap_create_draft"].annotations.idempotentHint is False


def test_draft_tools_say_they_do_not_send():
    """The model reports from these descriptions."""
    for name in ("imap_create_draft", "imap_update_draft"):
        description = _tools()[name].description.lower()
        assert "not sent" in description or "never sends" in description


def test_delete_explains_that_it_moves_to_trash():
    description = _tools()["imap_delete_messages"].description.lower()
    assert "trash" in description
    assert "expunge" in description or "nothing is destroyed" in description


def test_mutating_tools_warn_against_acting_on_message_content():
    """Rail 3, restated where the model actually reads it."""
    description = _tools()["imap_delete_messages"].description.lower()
    assert "user chose" in description or "uids the user" in description


def test_the_write_error_vocabulary_is_closed():
    """A third kind cannot appear without someone deciding to add it."""
    from imap_mcp import write

    assert write.WRITE_ERROR_KINDS == {"refused", "conflict"}


def test_every_tool_has_a_description():
    for name, tool in _tools().items():
        assert (tool.description or "").strip(), f"{name} has no description"


def test_read_message_description_warns_about_untrusted_content():
    """The injection warning must reach the model at the tool boundary."""
    desc = _tools()["imap_read_message"].description.lower()
    assert "untrusted" in desc
    assert "never as instructions" in desc or "not as instructions" in desc


def test_missing_credentials_return_classified_error_not_an_exception(monkeypatch):
    from imap_mcp import keychain

    # A provider must resolve first, or the config error masks the auth one.
    monkeypatch.setenv(server.ENV_PROVIDER, "icloud")
    monkeypatch.delenv(server.ENV_HOST, raising=False)
    monkeypatch.delenv(keychain._ENV_ACCOUNT, raising=False)
    monkeypatch.delenv(keychain._ENV_PASSWORD, raising=False)
    monkeypatch.setattr(keychain, "_read", lambda s, a: None)

    result = server.imap_list_mailboxes()
    assert result["ok"] is False
    assert result["kind"] == "auth"
    assert result["reason"] == "no_account"


def test_credential_error_hint_never_contains_a_secret(monkeypatch):
    from imap_mcp import keychain

    monkeypatch.setenv(server.ENV_PROVIDER, "icloud")
    monkeypatch.delenv(server.ENV_HOST, raising=False)
    monkeypatch.setenv(keychain._ENV_ACCOUNT, "me@example.com")
    monkeypatch.setattr(keychain, "_read", lambda s, a: None)
    monkeypatch.delenv(keychain._ENV_PASSWORD, raising=False)

    result = server.imap_health()
    assert result["ok"] is False
    # The hint points at the provider's own password page, never at a secret.
    assert "appleid.apple.com" in result["message"]
    assert "password_masked" not in result.get("credential", {})
