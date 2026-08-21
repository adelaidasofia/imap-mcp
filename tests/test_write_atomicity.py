"""Rail 4 — check and act share one scope.

Select-then-mutate on UIDs is a time-of-check/time-of-use race, per the
operating rule *A Read-Then-Act Safety Gate Is Atomic*. IMAP has no
transaction to put around it, so the scope here is one session with the
mailbox selected once, the target re-verified in the instant before its own
mutation, and a refusal on any sign the mailbox moved underneath.

What makes that sufficient rather than merely careful is a property of the
protocol: within one UIDVALIDITY epoch a UID is permanent and never reused,
so a UID either still names the same message or names nothing. It cannot
come to name a DIFFERENT message, which is the outcome a naive check-then-act
would otherwise produce. Both remaining ways state can move are tested below,
and both are refusals.
"""

from __future__ import annotations

from imap_mcp import server, write
from tests.fake_imap import FakeIMAP, install


def test_a_renumbered_mailbox_refuses_before_mutating_anything(monkeypatch):
    """UIDVALIDITY changed since the search: every UID now means something else."""
    fake = FakeIMAP(uidvalidity=99)
    install(monkeypatch, fake)

    result = server.imap_delete_messages(
        uids=[101, 102], mailbox="INBOX", expect_uidvalidity=42, dry_run=False
    )

    assert result["ok"] is False
    assert result["kind"] == "conflict"
    assert "renumbered" in result["message"]
    # The gate fired BEFORE any mutation, not after a partial one.
    assert fake.mutating_commands() == []
    assert fake.moved == []


def test_check_and_act_share_one_select(monkeypatch):
    """One SELECT for the whole batch, and it is writable."""
    fake = FakeIMAP()
    install(monkeypatch, fake)

    server.imap_delete_messages(uids=[101, 102], mailbox="INBOX", dry_run=False)

    selects = [c for c in fake.commands if c.startswith(("SELECT", "EXAMINE"))]
    assert len(selects) == 1, f"expected one SELECT, got {selects}"
    assert selects[0].startswith("SELECT"), "a mutation needs a writable session"
    assert fake.selected_readonly is False


def test_each_uid_is_verified_immediately_before_its_own_move(monkeypatch):
    """Ordering is the whole claim: verify, mutate, verify, mutate."""
    fake = FakeIMAP()
    install(monkeypatch, fake)

    server.imap_delete_messages(uids=[101, 102], mailbox="INBOX", dry_run=False)

    interesting = [
        c
        for c in fake.commands
        if c.startswith("SELECT") or "FETCH" in c or "MOVE" in c
    ]
    assert len(interesting) == 5
    assert interesting[0].startswith("SELECT") and "INBOX" in interesting[0]
    assert "FETCH 101" in interesting[1] and "HEADER.FIELDS" in interesting[1]
    assert "MOVE 101" in interesting[2]
    assert "FETCH 102" in interesting[3]
    assert "MOVE 102" in interesting[4]


def test_a_vanished_message_refuses_instead_of_moving_nothing(monkeypatch):
    """A MOVE on a missing UID would affect zero messages and report OK."""
    fake = FakeIMAP(messages={102: "two@example.com"})
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    assert result["ok"] is False
    assert result["kind"] == "conflict"
    assert "no longer in this mailbox" in result["message"]
    assert fake.moved == []


def test_a_uid_holding_a_different_message_is_refused():
    """When the caller says which message they meant, we check it."""
    import pytest

    fake = FakeIMAP(messages={101: "somebody-else@example.com"})

    with pytest.raises(write.StateConflictError):
        write.move_uids(
            fake,
            uids=[101],
            source_mailbox="INBOX",
            destination_mailbox="Deleted Messages",
            expect_message_ids={101: "the-one-i-picked@example.com"},
        )
    assert fake.moved == []


def test_a_concurrent_delete_inside_the_check_to_act_gap(monkeypatch, tmp_path):
    """The interleaving control: move state at the ONE moment it matters.

    `after_fetch` fires immediately after the verification FETCH returns and
    before the MOVE is issued — the exact window a TOCTOU lives in. A
    concurrent client removes the second message there. The batch must fail
    loudly, and the first message's move must still be recorded, or the mail
    that DID move would be stranded with no manifest.
    """
    monkeypatch.setenv("IMAP_MCP_VAULT_ROOT", str(tmp_path))
    calls = {"n": 0}

    def concurrent_client(server_state):
        calls["n"] += 1
        if calls["n"] == 2:
            server_state.messages.pop(102, None)

    fake = FakeIMAP(after_fetch=concurrent_client)
    install(monkeypatch, fake)

    result = server.imap_delete_messages(
        uids=[101, 102], mailbox="INBOX", dry_run=False
    )

    assert result["ok"] is False
    assert result["partial"] is True
    assert result["moved"] == 1
    # The one that moved is still fully accounted for.
    moved = result["undo_manifest"]["moved"]
    assert [m["uid"] for m in moved] == [101]
    assert moved[0]["to"] == "Deleted Messages"
    assert result["undo_manifest_path"] is not None


def test_marking_flags_honours_uidvalidity_too(monkeypatch):
    """The same gate on the non-move mutation path."""
    fake = FakeIMAP(uidvalidity=7)
    install(monkeypatch, fake)

    result = server.imap_mark_messages(
        uids=[101], mailbox="INBOX", read=True, expect_uidvalidity=42
    )

    assert result["ok"] is False
    assert result["kind"] == "conflict"
    assert fake.flag_changes == []


def test_verification_reads_headers_never_a_body(monkeypatch):
    """A body is attacker-controlled; verification must not touch one."""
    fake = FakeIMAP()
    install(monkeypatch, fake)

    server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    fetches = [c for c in fake.commands if "FETCH" in c]
    assert fetches, "expected a verification fetch"
    for command in fetches:
        assert "HEADER.FIELDS" in command
        assert "BODY.PEEK[]" not in command.replace(" ", "")
