"""Provider-agnostic IMAP core.

Cross-platform (stdlib `imaplib` + `ssl`) per the Mycelium cross-platform
rule — only `keychain.py` is macOS-specific. This module is the ONE place
that speaks IMAP; the MCP tool layer and the future memory-runtime-pro
adapter both sit on top of it. Endpoints come from `providers.py`, never
from a constant here, so adding a mail host is a table entry.

iCloud endpoint verified live 2026-08-18: imap.mail.me.com:993 serves a
valid Apple certificate (CN=imap.mail.me.com) and greets with

    * OK [CAPABILITY XAPPLEPUSHSERVICE IMAP4 IMAP4rev1 SASL-IR
          AUTH=ATOKEN AUTH=PLAIN AUTH=ATOKEN2 AUTH=XOAUTH2]

Note the advertised AUTH=XOAUTH2: iCloud speaks the mechanism, but Apple
publishes no way for a third party to OBTAIN such a token — ATOKEN/XOAUTH2
are for Apple's own clients. So AUTH=PLAIN with an app-specific password
remains the only door available to us, and "iCloud has no OAuth" means "no
public OAuth grant", not "the server refuses the mechanism".

There is still no probe at import time; the first `connect()` is the real
verification and fails loud with kind="transport" rather than degrading.

Two correctness rails worth naming, because both fail silently otherwise:

1. **BODY.PEEK[], never BODY[].** A bare `FETCH BODY[]` sets the \\Seen flag
   as a side effect, so a read-only sync would silently mark the user's
   unread mail as read. Every fetch here peeks.

2. **UIDVALIDITY is checked on every incremental run.** IMAP UIDs are only
   stable while a mailbox's UIDVALIDITY is unchanged. If the server renumbers
   (mailbox rebuilt, restored from backup), a stale `since_uid` silently
   points at unrelated messages and the sync skips real mail forever. On a
   mismatch we discard the checkpoint and report a full resync instead.
"""

from __future__ import annotations

import base64
import email
import email.policy
import imaplib
import re
import socket
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Iterator, Optional

# Endpoints live in providers.py. Nothing vendor-specific belongs here.

# imaplib's default is 10000 bytes per line, which truncates large headers.
imaplib._MAXLINE = max(getattr(imaplib, "_MAXLINE", 10000), 1_000_000)

DEFAULT_TIMEOUT = 30
# Hard ceiling on a single fetch so one call can never stream an entire
# mailbox into the model's context. The tool layer caps lower still.
MAX_FETCH = 200


class IMAPError(Exception):
    """Mirrors memory-runtime-pro `AdapterError` so the runtime port is a
    rename, not a redesign. `kind` uses the same closed vocabulary:
    auth | rate_limit | timeout | transport | filter | schema | unknown.
    """

    def __init__(self, message: str, *, kind: str = "unknown") -> None:
        super().__init__(message)
        self.kind = kind


class AuthError(IMAPError):
    def __init__(self, message: str) -> None:
        super().__init__(message, kind="auth")


@dataclass(frozen=True)
class Checkpoint:
    """Resumable IMAP cursor. Opaque to callers, but must round-trip."""

    mailbox: str
    uidvalidity: int
    last_uid: int

    def as_dict(self) -> dict[str, object]:
        return {
            "mailbox": self.mailbox,
            "uidvalidity": self.uidvalidity,
            "last_uid": self.last_uid,
        }

    @classmethod
    def from_dict(cls, raw: Optional[dict]) -> Optional["Checkpoint"]:
        if not raw:
            return None
        try:
            return cls(
                mailbox=str(raw["mailbox"]),
                uidvalidity=int(raw["uidvalidity"]),
                last_uid=int(raw["last_uid"]),
            )
        except (KeyError, TypeError, ValueError):
            # A malformed checkpoint must degrade to "no checkpoint" (full
            # resync), never to a wrong one.
            return None


def _classify(exc: BaseException) -> IMAPError:
    """Map a raw exception to the closed `kind` vocabulary.

    Never lets a provider message carrying the password escape: IMAP LOGIN
    failures echo the command line back in `imaplib.error`, which contains
    the credential. We replace the message entirely for auth failures.
    """
    if isinstance(exc, IMAPError):
        return exc
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return IMAPError("imap timeout", kind="timeout")
    if isinstance(exc, ssl.SSLError):
        return IMAPError("imap TLS failure", kind="transport")
    if isinstance(exc, imaplib.IMAP4.error):
        text = str(exc).lower()
        if "authentication" in text or "login" in text or "invalid credentials" in text:
            # Deliberately does NOT interpolate `exc` — it may contain the ASP.
            return AuthError(
                "the mail server rejected the app-specific password. Re-mint "
                "it with the provider (imap_list_providers gives the URL); "
                "most providers also require two-factor auth to be enabled."
            )
        if "throttl" in text or "too many" in text:
            return IMAPError("imap throttled", kind="rate_limit")
        return IMAPError("imap protocol error", kind="transport")
    if isinstance(exc, (OSError, socket.error)):
        return IMAPError("imap connection failure", kind="transport")
    return IMAPError("unexpected imap failure", kind="unknown")


# ---------------------------------------------------------------------------
# Mailbox name encoding (IMAP modified UTF-7, RFC 3501 §5.1.3)
# ---------------------------------------------------------------------------


def encode_mailbox(name: str) -> str:
    """Encode a mailbox name to IMAP modified UTF-7 and quote it.

    `imaplib` does NOT do this. An unencoded non-ASCII folder name
    ("Recibidos", "Borradores" are ASCII, but user folders often are not)
    raises a protocol error that reads like a missing folder.
    """
    out: list[str] = []
    buf: list[str] = []

    def flush() -> None:
        if not buf:
            return
        raw = "".join(buf).encode("utf-16-be")
        b64 = base64.b64encode(raw).decode("ascii").rstrip("=").replace("/", ",")
        out.append(f"&{b64}-")
        buf.clear()

    for ch in name:
        if ch == "&":
            flush()
            out.append("&-")
        elif 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append(ch)
        else:
            buf.append(ch)
    flush()
    # Escape the backslash FIRST, then the quote. RFC 3501 quoted strings
    # escape both, and doing only the quote leaves a name ending in a
    # backslash able to escape its own closing quote — `INBOX\` would go out
    # as `"INBOX\"`, and everything after it would be read by the server as
    # command syntax rather than as a mailbox name.
    body = "".join(out).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + body + '"'


_LIST_RE = re.compile(rb'\((?P<flags>[^)]*)\)\s+"(?P<delim>[^"]*)"\s+(?P<name>.+)')


def decode_mailbox(raw: bytes) -> str:
    """Decode an IMAP LIST response line into a plain mailbox name."""
    m = _LIST_RE.match(raw)
    name = m.group("name") if m else raw
    text = name.decode("ascii", "replace").strip().strip('"')
    if "&" not in text:
        return text
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] != "&":
            out.append(text[i])
            i += 1
            continue
        j = text.find("-", i)
        if j == -1:
            out.append(text[i:])
            break
        chunk = text[i + 1 : j]
        if chunk == "":
            out.append("&")
        else:
            pad = "=" * (-len(chunk.replace(",", "/")) % 4)
            try:
                out.append(
                    base64.b64decode(chunk.replace(",", "/") + pad).decode("utf-16-be")
                )
            except Exception:
                out.append(text[i : j + 1])
        i = j + 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


@contextmanager
def connect(
    account: str,
    password: str,
    *,
    host: str,
    port: int = 993,
    timeout: int = DEFAULT_TIMEOUT,
) -> Iterator[imaplib.IMAP4_SSL]:
    """Open an authenticated TLS IMAP session, always closing it.

    Certificate verification is left at Python's secure default
    (`ssl.create_default_context`) — hostname checked, CA chain verified.
    `host` is required: there is no default mail server, because guessing
    one would silently send a credential to the wrong operator.
    """
    conn: Optional[imaplib.IMAP4_SSL] = None
    try:
        context = ssl.create_default_context()
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=timeout)
        conn.login(account, password)
    except BaseException as exc:  # noqa: BLE001 - re-raised as classified
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass
        raise _classify(exc) from None
    try:
        yield conn
    finally:
        # NEVER `conn.close()`. imaplib's own docstring for CLOSE says
        # "Deleted messages are removed from writable mailbox" — it is an
        # implicit EXPUNGE. It is harmless on the read path, which only ever
        # opens mailboxes with EXAMINE, but the write plane selects
        # read-write, and a mailbox can already contain messages some OTHER
        # client flagged \Deleted. Closing such a session would permanently
        # destroy mail this package never touched, which is exactly the
        # failure the never-expunge rail exists to prevent.
        #
        # LOGOUT ends the session without expunging anything, and imaplib's
        # logout() shuts the socket down as well, so nothing leaks.
        try:
            conn.logout()
        except Exception:
            pass


def list_mailboxes(conn: imaplib.IMAP4_SSL) -> list[str]:
    """Return decoded mailbox names."""
    try:
        typ, data = conn.list()
    except BaseException as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if typ != "OK":
        raise IMAPError("LIST failed", kind="transport")
    return [decode_mailbox(line) for line in data if line]


def _select(conn: imaplib.IMAP4_SSL, mailbox: str) -> int:
    """Select a mailbox read-only and return its UIDVALIDITY.

    `readonly=True` (EXAMINE, not SELECT) is a second guard on top of
    BODY.PEEK: the server itself refuses flag changes for this session.
    """
    try:
        typ, _ = conn.select(encode_mailbox(mailbox), readonly=True)
        if typ != "OK":
            raise IMAPError(f"cannot select mailbox {mailbox!r}", kind="schema")
        typ, data = conn.response("UIDVALIDITY")
    except BaseException as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if not data or not data[0]:
        raise IMAPError("server did not report UIDVALIDITY", kind="schema")
    try:
        return int(re.sub(rb"[^0-9]", b"", data[0]) or b"0")
    except ValueError:
        raise IMAPError("unparseable UIDVALIDITY", kind="schema") from None


def _search_uids(
    conn: imaplib.IMAP4_SSL,
    *,
    since: Optional[datetime],
    since_uid: Optional[int],
    query: Optional[str],
    unseen_only: bool,
) -> list[int]:
    criteria: list[str] = []
    if since_uid is not None:
        # UID range is inclusive; +1 so a resumed run never re-emits the
        # message the checkpoint already covered.
        criteria += ["UID", f"{since_uid + 1}:*"]
    if since is not None:
        criteria += ["SINCE", since.strftime("%d-%b-%Y")]
    if unseen_only:
        criteria.append("UNSEEN")
    if query:
        # IMAP TEXT searches headers+body. Quote to keep spaces in one token
        # and neutralise the quote character so a crafted subject cannot
        # inject additional SEARCH keys.
        criteria += ["TEXT", '"' + query.replace("\\", "").replace('"', "") + '"']
    if not criteria:
        criteria = ["ALL"]
    try:
        typ, data = conn.uid("SEARCH", None, *criteria)
    except BaseException as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if typ != "OK":
        raise IMAPError("SEARCH failed", kind="transport")
    if not data or not data[0]:
        return []
    return sorted(int(x) for x in data[0].split())


def _fetch_message(conn: imaplib.IMAP4_SSL, uid: int) -> Optional[EmailMessage]:
    """Fetch one message with PEEK so \\Seen is never set."""
    try:
        typ, data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
    except BaseException as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if typ != "OK" or not data:
        return None
    for part in data:
        if isinstance(part, tuple) and len(part) >= 2 and part[1]:
            return email.message_from_bytes(part[1], policy=email.policy.default)
    return None


def fetch_messages(
    conn: imaplib.IMAP4_SSL,
    mailbox: str = "INBOX",
    *,
    since: Optional[datetime] = None,
    checkpoint: Optional[Checkpoint] = None,
    query: Optional[str] = None,
    unseen_only: bool = False,
    max_items: int = 50,
) -> tuple[list[tuple[int, EmailMessage]], Checkpoint, bool]:
    """Fetch up to `max_items` messages, oldest-first.

    Returns (messages, new_checkpoint, uidvalidity_reset). When
    `uidvalidity_reset` is True the caller's checkpoint was stale and the
    range was widened to a full resync — surface that, never swallow it.
    """
    max_items = max(1, min(int(max_items), MAX_FETCH))
    uidvalidity = _select(conn, mailbox)

    since_uid: Optional[int] = None
    reset = False
    if checkpoint is not None:
        if checkpoint.mailbox == mailbox and checkpoint.uidvalidity == uidvalidity:
            since_uid = checkpoint.last_uid
        else:
            reset = True

    uids = _search_uids(
        conn,
        since=since,
        since_uid=since_uid,
        query=query,
        unseen_only=unseen_only,
    )
    selected = uids[:max_items]

    out: list[tuple[int, EmailMessage]] = []
    for uid in selected:
        msg = _fetch_message(conn, uid)
        if msg is not None:
            out.append((uid, msg))

    high_water = selected[-1] if selected else (since_uid or 0)
    return (
        out,
        Checkpoint(mailbox=mailbox, uidvalidity=uidvalidity, last_uid=high_water),
        reset,
    )


def health(
    account: str, password: str, *, host: str, port: int = 993, source: str = "imap"
) -> dict[str, object]:
    """Probe reachability. Errors are SWALLOWED into ok=False, never raised —
    same contract as memory-runtime-pro `Adapter.health`.
    """
    started = datetime.now(timezone.utc)
    try:
        with connect(account, password, host=host, port=port) as conn:
            list_mailboxes(conn)
    except IMAPError as exc:
        return {
            "ok": False,
            "source": source,
            "kind": exc.kind,
            "message": str(exc),
            "latency_ms": None,
        }
    except BaseException as exc:  # noqa: BLE001
        classified = _classify(exc)
        return {
            "ok": False,
            "source": source,
            "kind": classified.kind,
            "message": str(classified),
            "latency_ms": None,
        }
    latency = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    return {
        "ok": True,
        "source": source,
        "kind": "ok",
        "message": None,
        "latency_ms": latency,
    }
