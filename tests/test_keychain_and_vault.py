"""Credential-handling and vault-write tests.

The credential tests care about one thing above all: a MISSING credential
must never be reportable as a working one, and a present one must never be
rendered in full.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from imap_mcp import keychain, vault


# --------------------------------------------------------------------------
# keychain
# --------------------------------------------------------------------------


def test_mask_never_reveals_prefix():
    masked = keychain.mask("abcd-efgh-ijkl-mnop")
    assert masked.endswith("mnop")
    assert "abcd" not in masked
    assert masked.startswith("*")


def test_mask_of_absent_is_explicit():
    assert keychain.mask(None) == "<absent>"
    assert keychain.mask("") == "<absent>"


def test_credential_status_three_states(monkeypatch):
    monkeypatch.delenv(keychain._ENV_ACCOUNT, raising=False)
    monkeypatch.delenv(keychain._ENV_PASSWORD, raising=False)
    monkeypatch.setattr(keychain, "_read", lambda s, a: None)

    assert keychain.credential_status()["reason"] == "no_account"

    monkeypatch.setenv(keychain._ENV_ACCOUNT, "me@icloud.com")
    assert keychain.credential_status()["reason"] == "no_password"

    monkeypatch.setattr(keychain, "_read", lambda s, a: "aaaa-bbbb-cccc-dddd")
    status = keychain.credential_status()
    assert status["configured"] is True
    assert status["reason"] == "present"
    assert status["password_masked"].endswith("dddd")
    assert "aaaa" not in status["password_masked"]


def test_keychain_wins_over_env(monkeypatch):
    """An env var must never silently shadow the Keychain value."""
    monkeypatch.setenv(keychain._ENV_PASSWORD, "from-env")
    monkeypatch.setattr(keychain, "_read", lambda s, a: "from-keychain")
    assert keychain.get_app_specific_password("me@icloud.com") == "from-keychain"


def test_asp_shaped_value_is_not_hex_mangled():
    """An app-specific password contains '-', so it can never trip the
    hex-decode path. Guards the decode heuristic against eating a real
    credential."""
    assert keychain._looks_hex_encoded("aaaa-bbbb-cccc-dddd") is False


def test_hex_predicate_positive_control():
    """Negative control needs a positive twin, or it proves nothing."""
    assert keychain._looks_hex_encoded("ab" * 20) is True


# --------------------------------------------------------------------------
# vault
# --------------------------------------------------------------------------


def _item(subject="Hello", sha="a" * 64, rel=None):
    return {
        "source": "icloud",
        "source_id": "x@y",
        "title": subject,
        "body": "body text",
        "created_at": datetime(2026, 8, 12, tzinfo=timezone.utc),
        "modified_at": datetime(2026, 8, 12, tzinfo=timezone.utc),
        "author": "a@b.com",
        "labels": ["INBOX"],
        "metadata": {"mailbox": "INBOX", "body_sha256": sha, "has_attachments": False},
        "relative_path": rel or "External Inputs/iCloud Mail/inbox/2026-08-12-hello.md",
    }


def test_write_then_unchanged_is_idempotent(tmp_path):
    first = vault.write_item(_item(), vault_root=tmp_path)
    assert first["status"] == "written"
    second = vault.write_item(_item(), vault_root=tmp_path)
    assert second["status"] == "unchanged"


def test_changed_body_rewrites(tmp_path):
    vault.write_item(_item(sha="a" * 64), vault_root=tmp_path)
    again = vault.write_item(_item(sha="b" * 64), vault_root=tmp_path)
    assert again["status"] == "written"


def test_path_traversal_is_contained(tmp_path):
    escaping = _item(rel="../../../../etc/evil.md")
    result = vault.write_item(escaping, vault_root=tmp_path)
    assert result["status"] == "error"
    assert result["reason"] == "path_escapes_vault"


def test_dry_run_writes_nothing(tmp_path):
    result = vault.write_item(_item(), vault_root=tmp_path, dry_run=True)
    assert result["status"] == "would_write"
    assert not list(tmp_path.rglob("*.md"))


def test_write_items_reports_root_and_counts(tmp_path):
    summary = vault.write_items([_item(), _item(subject="Two", rel="External Inputs/iCloud Mail/inbox/b.md")], vault_root=tmp_path)
    assert summary["vault_root"] == str(tmp_path)
    assert summary["total"] == 2
    assert summary["counts"]["written"] == 2
    assert summary["errors"] == []


def test_resolve_vault_root_reports_its_source(monkeypatch, tmp_path):
    monkeypatch.setenv(vault.ENV_VAULT_ROOT, str(tmp_path))
    root, source = vault.resolve_vault_root()
    assert root == tmp_path
    assert source == "env:" + vault.ENV_VAULT_ROOT

    monkeypatch.delenv(vault.ENV_VAULT_ROOT, raising=False)
    _, source = vault.resolve_vault_root()
    assert source == "fallback:default"


def test_rendered_note_marks_content_untrusted(tmp_path):
    note = vault.render_note(_item())
    assert "content_is_untrusted: true" in note
    assert "source: imap" in note


def test_checkpoint_round_trip(tmp_path):
    assert vault.load_checkpoint("INBOX", vault_root=tmp_path) is None
    vault.save_checkpoint(
        "INBOX", {"mailbox": "INBOX", "uidvalidity": 7, "last_uid": 42}, vault_root=tmp_path
    )
    got = vault.load_checkpoint("INBOX", vault_root=tmp_path)
    assert got == {"mailbox": "INBOX", "uidvalidity": 7, "last_uid": 42}
