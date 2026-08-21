"""Rail 5 — bulk is capped, previewed, and reversible.

The three failure modes this closes, in the order they bite:

* acting on more mail than a person can check,
* acting at all when they meant to look first,
* and moving mail with no record of where it went.

The cap is a REFUSAL, never a truncation. Silently doing the first 25 of 300
and reporting success is the worst available behaviour: the caller believes
all 300 are done and has no signal otherwise.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from imap_mcp import server, write
from tests.fake_imap import FakeIMAP, install

BULK_TOOLS = (
    "imap_delete_messages",
    "imap_archive_messages",
    "imap_move_messages",
    "imap_update_draft",
)


def test_dry_run_is_the_default_on_every_destructive_tool():
    for name in BULK_TOOLS:
        default = inspect.signature(getattr(server, name)).parameters["dry_run"].default
        assert default is True, f"{name} does not default to a preview"


def test_a_dry_run_changes_nothing_and_never_opens_a_writable_session(monkeypatch):
    """A preview has no write capability to misuse: it uses EXAMINE."""
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101, 102], mailbox="INBOX")

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["count"] == 2
    assert fake.mutating_commands() == []
    assert fake.selected_readonly is True
    assert all(c.startswith("EXAMINE") for c in fake.commands if "SELECT" in c or c.startswith("EXAMINE"))


def test_a_dry_run_names_each_message_and_its_destination(monkeypatch):
    fake = FakeIMAP()
    install(monkeypatch, fake)

    rows = server.imap_delete_messages(uids=[101, 102], mailbox="INBOX")["messages"]

    assert [r["uid"] for r in rows] == [101, 102]
    for row in rows:
        assert row["status"] == "would_move"
        assert row["from"] == "INBOX"
        assert row["to"] == "Deleted Messages"
        assert row["message_id"]


def test_a_dry_run_reports_a_message_that_is_already_gone(monkeypatch):
    """The preview is honest about what it could not find."""
    fake = FakeIMAP(messages={101: "one@example.com"})
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101, 999], mailbox="INBOX")

    statuses = {r["uid"]: r["status"] for r in result["messages"]}
    assert statuses == {101: "would_move", 999: "unavailable"}
    assert result["count"] == 1


def test_over_the_cap_is_refused_not_truncated(monkeypatch):
    fake = FakeIMAP()
    install(monkeypatch, fake)

    too_many = list(range(1, write.MAX_BULK + 2))
    result = server.imap_delete_messages(uids=too_many, mailbox="INBOX", dry_run=False)

    assert result["ok"] is False
    assert result["kind"] == "refused"
    assert "not a truncation" in result["message"]
    assert fake.mutating_commands() == []


def test_the_cap_applies_to_previews_too(monkeypatch):
    """Otherwise a 300-message preview teaches the model the call is fine."""
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=list(range(1, 200)), mailbox="INBOX")

    assert result["ok"] is False
    assert result["kind"] == "refused"


def test_the_inner_cap_holds_on_its_own():
    """The cap exists at two layers, so each needs pinning separately.

    The tool layer refuses first, which means a tool-level test passes even
    with this one deleted — the mutation harness found exactly that. Calling
    write.move_uids directly is the only way to prove the inner guard is
    doing anything, and it is the guard that protects any future caller that
    is not the MCP tool (the memory-runtime-pro port, for one).
    """
    import pytest

    fake = FakeIMAP()
    with pytest.raises(write.RailViolation) as caught:
        write.move_uids(
            fake,
            uids=list(range(1, write.MAX_BULK + 2)),
            source_mailbox="INBOX",
            destination_mailbox="Archive",
        )
    assert "not a truncation" in str(caught.value)
    assert fake.mutating_commands() == []


def test_the_inner_cap_holds_on_flag_changes_too():
    import pytest

    fake = FakeIMAP()
    with pytest.raises(write.RailViolation):
        write.store_flags(
            fake,
            uids=list(range(1, write.MAX_BULK + 2)),
            mailbox="INBOX",
            flags=["\\Seen"],
            add=True,
        )
    assert fake.flag_changes == []


def test_the_cap_applies_to_flag_changes(monkeypatch):
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_mark_messages(
        uids=list(range(1, 200)), mailbox="INBOX", read=True
    )

    assert result["ok"] is False
    assert result["kind"] == "refused"
    assert fake.flag_changes == []


def test_the_undo_manifest_names_every_message_and_where_it_went(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAP_MCP_VAULT_ROOT", str(tmp_path))
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_archive_messages(
        uids=[101, 102], mailbox="INBOX", dry_run=False
    )

    manifest = result["undo_manifest"]
    assert manifest["operation"] == "archive"
    assert manifest["count"] == 2
    assert len(manifest["moved"]) == 2
    for entry in manifest["moved"]:
        assert entry["from"] == "INBOX"
        assert entry["to"] == "Archive"
        assert entry["message_id"]
        assert entry["destination_uid"] is not None
        assert entry["mechanism"] == "UID MOVE"
    assert "reverse_with" in manifest


def test_the_undo_manifest_survives_the_conversation(monkeypatch, tmp_path):
    """On disk, because a response scrolls away and the mail stays moved."""
    monkeypatch.setenv("IMAP_MCP_VAULT_ROOT", str(tmp_path))
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    path = Path(result["undo_manifest_path"])
    assert path.exists()
    assert path.parent == tmp_path / ".imap-mcp" / "undo"
    stored = json.loads(path.read_text())
    assert stored["moved"][0]["uid"] == 101
    assert stored["moved"][0]["to"] == "Deleted Messages"


def test_a_manifest_write_failure_is_reported_not_swallowed(monkeypatch, tmp_path):
    """A false reversibility claim is worse than a visible failure."""
    monkeypatch.setenv("IMAP_MCP_VAULT_ROOT", str(tmp_path))
    fake = FakeIMAP()
    install(monkeypatch, fake)

    from imap_mcp import vault

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(vault.Path, "mkdir", explode)

    result = server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    assert result["undo_manifest_path"] is None
    assert "disk full" in result["undo_manifest_error"]
    # The manifest is still in the response even when the disk write failed.
    assert result["undo_manifest"]["moved"][0]["uid"] == 101


def test_duplicate_uids_are_collapsed(monkeypatch):
    """A repeated UID would move once and then fail its own re-verification,
    reporting a state conflict for what is really a duplicated argument."""
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_delete_messages(
        uids=[101, 101, 102, 101], mailbox="INBOX", dry_run=False
    )

    assert result["ok"] is True
    assert result["moved"] == 2
    assert [m["uid"] for m in result["undo_manifest"]["moved"]] == [101, 102]


def test_nonsense_uids_are_rejected_before_connecting(monkeypatch):
    fake = FakeIMAP()
    install(monkeypatch, fake)

    for bad in ([0], [-5], [101, -1]):
        result = server.imap_delete_messages(uids=bad, mailbox="INBOX", dry_run=False)
        assert result["ok"] is False
        assert result["kind"] == "schema"
    assert fake.mutating_commands() == []


def test_moving_to_the_same_folder_is_refused(monkeypatch):
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_move_messages(
        uids=[101], destination="INBOX", mailbox="INBOX", dry_run=False
    )

    assert result["ok"] is False
    assert fake.moved == []
