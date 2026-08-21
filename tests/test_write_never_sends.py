"""Rail 2 — this package creates drafts and cannot send.

"Cannot send" is structural rather than promised, and it holds at three
independent layers: no SMTP endpoint exists in the provider table, so there
is nothing to connect to; no SMTP client is imported anywhere, so there is
nothing to connect WITH; and the write chokepoint refuses send-shaped verbs,
so a hand-rolled attempt fails closed. Same posture as the Gmail compose
connector (MYC-2694), where the scope technically permits sending and the
app-level rail is what actually prevents it.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path

import pytest

from imap_mcp import providers, server, write
from tests.fake_imap import FakeIMAP, install

PACKAGE = Path(__file__).resolve().parent.parent / "imap_mcp"


def test_send_shaped_verbs_are_refused():
    for verb in ("SEND", "SMTP", "MAIL FROM", "RCPT TO", "SUBMIT", "BURL", "SENDMAIL"):
        with pytest.raises(write.SendAttemptError):
            write._assert_safe_verb(verb)


def test_no_smtp_client_is_imported_anywhere():
    """An import is the cheapest possible tell that someone added sending."""
    banned = {"smtplib", "aiosmtplib", "aiosmtpd"}
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {(node.module or "").split(".")[0]}
            else:
                continue
            assert not (names & banned), f"{path.name} imports an SMTP client"


def test_provider_profiles_carry_no_smtp_endpoint():
    """No host, no port, nothing for a send path to reach."""
    fields = {f.name for f in dataclasses.fields(providers.Provider)}
    assert not any("smtp" in name.lower() for name in fields)
    for provider in providers.PROVIDERS.values():
        for value in dataclasses.asdict(provider).values():
            assert "smtp" not in str(value).lower()


def test_no_smtp_ports_appear_in_the_package():
    """587 and 465 are submission ports; 993 is the only port we speak."""
    for path in PACKAGE.glob("*.py"):
        text = path.read_text()
        for port in ("587", "465", "25565"):
            assert not re.search(rf"\b{port}\b", text), f"{path.name} names port {port}"


def test_the_write_plane_exposes_no_send_function():
    """No callable named like a send. Exception classes are the point of
    the rail, not a violation of it, so only functions are examined."""
    import inspect

    for name in dir(write):
        if name.startswith("__"):
            continue
        attribute = getattr(write, name)
        if not inspect.isfunction(attribute):
            continue
        assert not re.match(r"^_?(send|deliver|submit|transmit)", name, re.I), name


def test_creating_a_draft_only_appends(monkeypatch):
    fake = FakeIMAP()
    install(monkeypatch, fake)

    result = server.imap_create_draft(
        to=["someone@example.com"], subject="Hello", body="Body text."
    )

    assert result["ok"] is True
    assert result["sent"] is False
    assert result["mailbox"] == "Drafts"
    assert len(fake.appended) == 1
    assert "\\Draft" in fake.appended[0]["flags"]
    # APPEND is the only mailbox mutation a draft performs.
    assert [c for c in fake.mutating_commands() if not c.startswith("APPEND")] == []
    assert not fake.issued("SEND")


def test_the_draft_tool_says_plainly_that_nothing_was_sent(monkeypatch):
    """The model reports from this payload; it must not read as 'sent'."""
    fake = FakeIMAP()
    install(monkeypatch, fake)
    result = server.imap_create_draft(to=["a@example.com"], subject="s", body="b")
    assert result["sent"] is False
    assert "not" in result["note"].lower() or "nothing was sent" in result["note"].lower()


def test_a_subject_cannot_inject_extra_headers():
    """A crafted subject must not be able to add a Bcc to the draft."""
    with pytest.raises(Exception):
        write.build_draft(
            to=["a@example.com"],
            subject="Hi\r\nBcc: attacker@example.com",
            body="x",
        )
