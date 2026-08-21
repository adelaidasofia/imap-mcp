"""Rail 1 — nothing here can permanently destroy mail.

Two independent guards, because one is not enough. EXPUNGE is refused as a
verb, AND `\\Deleted` is refused as a flag. The second matters more than it
looks: IMAP CLOSE implicitly expunges every `\\Deleted` message in a
read-write mailbox, and `imap_client.connect()` calls `conn.close()` on the
way out. Banning only the verb would leave the teardown able to destroy mail
that some other code path had flagged.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from imap_mcp import server, write
from tests.fake_imap import (
    SPANISH_FOLDERS,
    FakeIMAP,
    install,
)

PACKAGE = Path(__file__).resolve().parent.parent / "imap_mcp"


def test_expunge_verb_is_refused():
    for verb in ("EXPUNGE", "UID EXPUNGE", "uid expunge", "  EXPUNGE  "):
        with pytest.raises(write.ExpungeAttemptError):
            write._assert_safe_verb(verb)


def test_deleted_flag_is_refused():
    for flag in ("\\Deleted", "Deleted", "\\DELETED", "\\deleted"):
        with pytest.raises(write.DeletedFlagError):
            write._assert_safe_flags([flag])


def test_deleted_flag_is_refused_even_beside_a_legal_flag():
    """A batch containing one banned flag fails whole, not partially."""
    with pytest.raises(write.DeletedFlagError):
        write._assert_safe_flags(["\\Seen", "\\Deleted"])


def test_unknown_verbs_fail_closed():
    """An unlisted verb is refused rather than passed to the server."""
    for verb in ("SETACL", "RENAME", "SUBSCRIBE", "GETMETADATA"):
        with pytest.raises(write.RailViolation):
            write._assert_safe_verb(verb)


def test_the_chokepoint_refuses_deleted_even_when_called_directly():
    """The verb gate is not enough on its own.

    `UID STORE` is allowlisted, and its ARGUMENTS decide the flags — so a
    caller that skipped `_assert_safe_flags` could otherwise set \\Deleted
    through an approved verb. The chokepoint re-checks, so the guarantee
    does not rest on every call site remembering.
    """
    from tests.fake_imap import FakeIMAP

    fake = FakeIMAP()
    with pytest.raises(write.DeletedFlagError):
        write._mutate(fake, "UID STORE", "101", "+FLAGS", "(\\Deleted)")
    assert fake.flag_changes == []


def test_no_module_calls_expunge():
    """No `.expunge(` anywhere in the package, in any module."""
    for path in PACKAGE.glob("*.py"):
        assert ".expunge(" not in path.read_text(), f"{path.name} calls expunge()"


def test_every_mutate_call_site_uses_an_allowlisted_verb():
    """Structural, not behavioural: read the AST and check each call.

    A behavioural test only covers the paths it happens to walk. This reads
    every `_mutate(...)` call in the write plane and asserts the verb is a
    literal from the allowlist, so a new call site cannot introduce a verb
    that no test exercises.
    """
    tree = ast.parse((PACKAGE / "write.py").read_text())
    sites = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name != "_mutate":
            continue
        sites += 1
        verb = node.args[1]
        assert isinstance(verb, ast.Constant), "verb must be a literal, not computed"
        assert verb.value in write._ALLOWED_MUTATIONS, f"unlisted verb {verb.value!r}"
    assert sites >= 3, "expected the move, store, and append call sites"


def test_delete_moves_to_trash_and_never_expunges(monkeypatch):
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    assert result["ok"] is True
    assert result["destination"] == "Deleted Messages"
    assert fake.moved == [(101, '"Deleted Messages"')]
    assert not fake.issued("EXPUNGE")
    assert not fake.issued("\\Deleted")
    assert fake.flag_changes == []


def test_delete_resolves_a_spanish_trash_folder(monkeypatch):
    """The reason resolution is SPECIAL-USE first: no English name exists."""
    fake = FakeIMAP(folders=SPANISH_FOLDERS)
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    assert result["ok"] is True
    assert result["destination"] == "Papelera"
    assert result["destination_resolved_by"] == "special-use"


def test_teardown_never_closes_a_mailbox(monkeypatch):
    """CLOSE is an implicit EXPUNGE, and the write plane selects read-write.

    A mailbox can already hold messages some OTHER client flagged \\Deleted.
    Closing a writable session would destroy them permanently — mail this
    package never touched — so the session ends with LOGOUT alone.

    This drives the REAL `imap_client.connect`, because the teardown IS the
    thing under test; a fake connection would replace the code it is meant
    to prove.
    """
    from imap_mcp import imap_client

    fake = FakeIMAP()
    monkeypatch.setattr(
        imap_client.imaplib, "IMAP4_SSL", lambda *a, **k: fake
    )

    with imap_client.connect("me@example.com", "pw", host="imap.example.com") as conn:
        conn.select("INBOX", readonly=False)

    assert "CLOSE" not in fake.commands, "teardown closed a writable mailbox"
    assert "LOGOUT" in fake.commands


def test_a_mailbox_named_like_the_flag_is_still_usable(monkeypatch):
    """iCloud's trash is *named* "Deleted Messages".

    A \\Deleted guard that matches on the word rather than the flag would
    refuse the one move that makes deletion recoverable. Caught in review;
    kept as a control so the guard cannot be re-broadened.
    """
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    assert result["ok"] is True
    assert result["destination"] == "Deleted Messages"


def test_a_mailbox_name_cannot_escape_its_quoted_string():
    """A trailing backslash would otherwise close the quote early and let the
    rest of the name be read by the server as command syntax."""
    from imap_mcp import imap_client

    encoded = imap_client.encode_mailbox("INBOX\\")
    assert encoded == '"INBOX\\\\"'
    assert not encoded.endswith('\\"') or encoded.endswith('\\\\"')


def test_a_server_without_MOVE_is_refused_not_downgraded(monkeypatch):
    """The classic fallback is COPY + \\Deleted + EXPUNGE. We refuse instead."""
    fake = FakeIMAP(capabilities=("IMAP4REV1",))
    install(monkeypatch, fake)

    result = server.imap_delete_messages(uids=[101], mailbox="INBOX", dry_run=False)

    assert result["ok"] is False
    assert result["kind"] == "refused"
    assert "MOVE" in result["message"]
    assert fake.mutating_commands() == []
