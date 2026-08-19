"""IMAP core tests that need no network.

The two rails these lock down are the ones that fail SILENTLY in production:
the checkpoint must never resolve to a wrong-but-plausible cursor, and an
auth failure must never echo the credential back in its message.
"""

from __future__ import annotations

import imaplib
import socket
import ssl

from imap_mcp import imap_client as ic


# --------------------------------------------------------------------------
# Checkpoint
# --------------------------------------------------------------------------


def test_checkpoint_round_trip():
    cp = ic.Checkpoint(mailbox="INBOX", uidvalidity=7, last_uid=42)
    assert ic.Checkpoint.from_dict(cp.as_dict()) == cp


def test_malformed_checkpoint_degrades_to_none_not_a_wrong_cursor():
    for bad in (None, {}, {"mailbox": "INBOX"}, {"mailbox": "I", "uidvalidity": "x", "last_uid": 1}):
        assert ic.Checkpoint.from_dict(bad) is None


# --------------------------------------------------------------------------
# Error classification
# --------------------------------------------------------------------------


def test_auth_failure_message_never_echoes_the_credential():
    """imaplib echoes the failed command — which contains the password."""
    secret = "abcd-efgh-ijkl-mnop"
    raw = imaplib.IMAP4.error(
        f'LOGIN command error: BAD [b\'me@icloud.com "{secret}"\'] authentication failed'
    )
    classified = ic._classify(raw)
    assert classified.kind == "auth"
    assert secret not in str(classified)
    assert "app-specific password" in str(classified)


def test_kind_vocabulary_is_closed():
    allowed = {"auth", "rate_limit", "timeout", "transport", "filter", "schema", "unknown"}
    cases = [
        socket.timeout("t"),
        ssl.SSLError("tls"),
        imaplib.IMAP4.error("too many connections"),
        imaplib.IMAP4.error("some other protocol thing"),
        OSError("conn refused"),
        RuntimeError("who knows"),
    ]
    for exc in cases:
        assert ic._classify(exc).kind in allowed


def test_throttle_is_classified_as_rate_limit():
    assert ic._classify(imaplib.IMAP4.error("Too many simultaneous")).kind == "rate_limit"


def test_existing_imap_error_passes_through_unchanged():
    original = ic.IMAPError("already classified", kind="schema")
    assert ic._classify(original) is original


# --------------------------------------------------------------------------
# Mailbox name encoding (RFC 3501 modified UTF-7)
# --------------------------------------------------------------------------


def test_ascii_mailbox_is_quoted():
    assert ic.encode_mailbox("Sent Messages") == '"Sent Messages"'


def test_ampersand_is_escaped():
    assert ic.encode_mailbox("R&D") == '"R&-D"'


def test_non_ascii_mailbox_round_trips():
    for name in ("Enviados", "Borradores", "Café", "受信箱", "Prüfung"):
        encoded = ic.encode_mailbox(name).strip('"')
        assert ic.decode_mailbox(encoded.encode("ascii")) == name


def test_decode_handles_a_list_response_line():
    line = b'(\\HasNoChildren) "/" "INBOX"'
    assert ic.decode_mailbox(line) == "INBOX"


def test_max_fetch_is_bounded():
    assert ic.MAX_FETCH <= 200
