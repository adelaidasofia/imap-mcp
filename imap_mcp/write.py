"""The write plane: the ONLY module in this package that mutates a mailbox.

`imap_client.py` reads and never mutates; this module mutates and never
reads a body. Splitting them that way is what makes the rails below
checkable by a test rather than promised by a docstring — the read module
can be asserted to contain no mutating verb, and this module can be
asserted to contain no body fetch and no send.

Five rails, each with a negative control in `tests/`:

1. **Never EXPUNGE, and never even flag `\\Deleted`.** Delete means MOVE to
   the provider's Trash. Raw `\\Deleted` + EXPUNGE destroys mail with no
   recovery path. Banning the verb alone would not be enough: IMAP `CLOSE`
   *implicitly expunges* every `\\Deleted` message in a read-write mailbox,
   and `imap_client.connect()` calls `conn.close()` in its teardown. So the
   flag is banned too, which makes the teardown harmless by construction —
   you cannot expunge what was never flagged.

2. **Never send.** A draft is an APPEND into the Drafts folder. Sending is
   SMTP: a different protocol, a different port, and deliberately absent
   from `providers.py`, so there is no host for a send path to reach. This
   module additionally refuses any send-shaped verb and exposes no send
   function. Same posture as the Gmail compose connector (MYC-2694), where
   "never send" is an app-level rail rather than a scope limit.

3. **Message content can never reach a mutation.** Every mutating entry
   point here takes integer UIDs the caller supplied. None takes a query, a
   rule, or a filter, so "delete everything from the CFO" cannot be
   expressed by anything except a person choosing those messages. This
   module never imports `normalize` and never fetches a body — the only
   FETCH it issues is for the Message-ID header, used to confirm a UID still
   names the message the caller meant.

4. **Read-then-act is one scope.** Check and mutation share a single
   session with the mailbox selected once, and the target is re-verified
   immediately before the mutation. See `move_uids` for why that is
   sufficient on IMAP specifically.

5. **Bulk is capped and reversible.** `MAX_BULK` is a refusal, not a
   truncation, and every move returns a record naming where the message
   went.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Iterable, Optional

from imap_mcp.imap_client import IMAPError, _classify, encode_mailbox

# NOTE: `normalize` is deliberately NOT imported. It extracts message bodies,
# and nothing in the write plane may read a body. Enforced by
# tests/test_write_no_injection.py.

# Hard ceiling on one bulk operation. Over this we REFUSE; we never silently
# act on the first N, because a caller who asked for 300 and got 25 with no
# error would reasonably believe all 300 were done.
MAX_BULK = 25

# The write plane adds exactly two `kind` values to the read vocabulary
# (auth | rate_limit | timeout | transport | filter | schema | unknown):
#
#   refused  — a safety rail declined the operation. Never retry blindly.
#   conflict — mailbox state moved between the check and the act; the
#              operation was abandoned before mutating anything.
#
# Listed here so the memory-runtime-pro port inherits the same closed set,
# and asserted by tests/test_write_rails.py so a third value cannot appear
# without someone deciding to add it.
WRITE_ERROR_KINDS = frozenset({"refused", "conflict"})


class RailViolation(IMAPError):
    """A safety rail refused. Always a bug or an attack, never a retry."""

    def __init__(self, message: str) -> None:
        super().__init__(message, kind="refused")


class ExpungeAttemptError(RailViolation):
    """Something tried to permanently destroy mail. Fail closed."""


class SendAttemptError(RailViolation):
    """Something tried to send. This server creates drafts only."""


class DeletedFlagError(RailViolation):
    """Something tried to set \\Deleted, which CLOSE would later expunge."""


class StateConflictError(IMAPError):
    """The target moved between the check and the act. Nothing was mutated."""

    def __init__(self, message: str) -> None:
        super().__init__(message, kind="conflict")


class PartialMoveError(IMAPError):
    """A batch failed after some messages had already moved.

    Carries the records for the moves that DID happen, so the caller can
    still write the undo manifest. Without this the failure path would move
    mail and then lose the only record of where it went, which is a worse
    outcome than the original error — "reversible" has to hold on the
    unhappy path too, or it is not a property.
    """

    def __init__(self, message: str, records: list, *, kind: str = "transport") -> None:
        super().__init__(message, kind=kind)
        self.records = records


# ---------------------------------------------------------------------------
# The verb + flag chokepoint
# ---------------------------------------------------------------------------

# Every mutation this module may perform. An unknown verb fails CLOSED rather
# than being passed through to the server, so adding a capability is a
# deliberate edit here and not an accident somewhere else.
_ALLOWED_MUTATIONS = frozenset({"UID MOVE", "UID COPY", "UID STORE", "APPEND"})

# Verbs that destroy mail. Checked before the allowlist so the error names the
# real problem ("this would destroy mail") instead of "unknown verb".
_EXPUNGE_RE = re.compile(r"\bEXPUNGE\b", re.I)

# Verbs and tokens that would put mail on the wire. IMAP has no send command,
# so any of these means someone bolted SMTP onto the wrong module.
_SEND_RE = re.compile(
    r"\b(SEND|SMTP|MAIL\s+FROM|RCPT\s+TO|SUBMIT|BURL|SENDMAIL)\b", re.I
)

# `\Deleted` is banned outright — see rail 1. The rest of the RFC 3501
# system flags are fine: they are metadata a user can toggle back.
_ALLOWED_FLAGS = frozenset({"\\Seen", "\\Flagged", "\\Answered", "\\Draft"})

# Two spellings, deliberately different in strictness.
#
# When parsing a single flag TOKEN, a bare "Deleted" with no backslash is
# still an attempt to set the flag, so the backslash is optional.
#
# When scanning a whole command ARGUMENT it must NOT be: iCloud's trash
# folder is *named* "Deleted Messages", so the loose pattern would refuse
# the very move that makes deletion safe. In an argument only the real flag
# form counts.
_DELETED_FLAG_RE = re.compile(r"\\?\bDELETED\b", re.I)
_DELETED_FLAG_IN_ARG_RE = re.compile(r"\\DELETED\b", re.I)


def _assert_safe_verb(verb: str) -> str:
    """The single gate every mutating command passes through.

    Order matters: destructive and send-shaped verbs are named explicitly
    before the allowlist runs, so the failure says what was actually wrong.
    """
    normalised = " ".join(str(verb).split()).upper()
    if _EXPUNGE_RE.search(normalised):
        raise ExpungeAttemptError(
            f"refusing {normalised!r}: EXPUNGE destroys mail permanently. "
            "Delete moves the message to Trash instead, which is recoverable."
        )
    if _SEND_RE.search(normalised):
        raise SendAttemptError(
            f"refusing {normalised!r}: this server creates drafts and never "
            "sends. Sending is SMTP, which this package does not speak. A "
            "person sends the draft from their own mail client."
        )
    if normalised not in _ALLOWED_MUTATIONS:
        raise RailViolation(
            f"refusing {normalised!r}: not in the write plane's allowlist "
            f"({', '.join(sorted(_ALLOWED_MUTATIONS))})."
        )
    return normalised


def _assert_safe_flags(flags: Iterable[str]) -> tuple[str, ...]:
    """Reject `\\Deleted`; reject anything not on the allowlist."""
    out: list[str] = []
    for raw in flags:
        flag = str(raw).strip()
        if _DELETED_FLAG_RE.search(flag):
            raise DeletedFlagError(
                "refusing to set \\Deleted: IMAP CLOSE implicitly expunges "
                "\\Deleted messages, so this would destroy mail at session "
                "teardown. Move the message to Trash instead."
            )
        canonical = "\\" + flag.lstrip("\\").capitalize()
        if canonical not in _ALLOWED_FLAGS:
            raise RailViolation(
                f"refusing flag {flag!r}: allowed flags are "
                f"{', '.join(sorted(_ALLOWED_FLAGS))}."
            )
        out.append(canonical)
    return tuple(out)


def _mutate(conn: Any, verb: str, *args: Any) -> tuple[str, list]:
    """Issue one mutating command. THE chokepoint — nothing else may.

    Split UID commands into ("UID", "MOVE", ...) here rather than at each
    call site so the verb string that gets gated is the same string that
    reaches the server.
    """
    checked = _assert_safe_verb(verb)
    # The verb is not the whole command. `UID STORE` is allowlisted, and its
    # ARGUMENTS decide which flags get set — so a direct call could still
    # smuggle \Deleted past the verb gate. Re-check here, at the chokepoint,
    # so the guarantee does not depend on every caller remembering to use
    # `_assert_safe_flags` first.
    for argument in args:
        if isinstance(argument, str) and _DELETED_FLAG_IN_ARG_RE.search(argument):
            raise DeletedFlagError(
                f"refusing {checked} with {argument!r}: setting \\Deleted "
                "lets a later CLOSE expunge the message. Move it to Trash."
            )
    try:
        if checked.startswith("UID "):
            typ, data = conn.uid(checked.split(" ", 1)[1], *args)
        else:
            typ, data = conn.append(*args)
    except IMAPError:
        raise
    except BaseException as exc:  # noqa: BLE001 - re-raised as classified
        raise _classify(exc) from None
    if typ != "OK":
        raise IMAPError(f"{checked} failed: {typ}", kind="transport")
    return typ, list(data or [])


# ---------------------------------------------------------------------------
# Special-folder resolution (RFC 6154 SPECIAL-USE, then the provider profile)
# ---------------------------------------------------------------------------

_SPECIAL_USE = {"drafts": r"\\Drafts", "trash": r"\\Trash", "archive": r"\\Archive"}

_LIST_LINE_RE = re.compile(rb'\((?P<flags>[^)]*)\)\s+"(?P<delim>[^"]*)"\s+(?P<name>.+)')


def _list_with_flags(conn: Any) -> list[tuple[str, str]]:
    """Return (mailbox_name, flags_blob) for every folder the server lists."""
    try:
        typ, data = conn.list()
    except BaseException as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if typ != "OK":
        raise IMAPError("LIST failed", kind="transport")

    from imap_mcp.imap_client import decode_mailbox

    out: list[tuple[str, str]] = []
    for line in data or []:
        if not line:
            continue
        raw = line if isinstance(line, bytes) else str(line).encode()
        m = _LIST_LINE_RE.match(raw)
        flags = m.group("flags").decode("ascii", "replace") if m else ""
        out.append((decode_mailbox(raw), flags))
    return out


def resolve_special_folder(
    conn: Any, provider: Any, kind: str
) -> tuple[str, str]:
    """Find the real, correctly-cased name of Drafts / Trash / Archive.

    Returns (mailbox_name, how_it_was_resolved) and never guesses in
    silence — the same honesty contract `vault.py` uses for `root_source`.

    The server's own SPECIAL-USE attribute wins because it is the only
    source that is right in every locale: a Spanish mailbox spells Trash
    "Papelera", and no table of English names will ever cover that. The
    provider profile is the fallback for servers that do not publish the
    attribute, and an exact case-insensitive match against the real folder
    list is the last resort. If none of the three resolve, this raises
    rather than inventing a folder name — creating a stray "Trash" folder
    and moving someone's mail into it is worse than refusing.
    """
    if kind not in _SPECIAL_USE:
        raise RailViolation(f"unknown special folder {kind!r}")

    folders = _list_with_flags(conn)
    attribute = _SPECIAL_USE[kind]

    for name, flags in folders:
        if re.search(attribute, flags, re.I):
            return name, "special-use"

    known = {name.lower(): name for name, _ in folders}
    candidates: tuple[str, ...] = getattr(provider, f"{kind}_mailboxes", ()) or ()
    for candidate in candidates:
        if candidate.lower() in known:
            # Return the server's spelling, not ours — casing must match.
            return known[candidate.lower()], "provider-profile"

    raise IMAPError(
        f"cannot find the {kind} folder on this account. The server "
        f"published no \\{kind.capitalize()} SPECIAL-USE attribute and none "
        f"of {list(candidates)} exists. Run imap_list_mailboxes and pass the "
        "folder name explicitly.",
        kind="schema",
    )


# ---------------------------------------------------------------------------
# Atomic read-then-act
# ---------------------------------------------------------------------------


def select_writable(conn: Any, mailbox: str) -> int:
    """SELECT (read-write) and return UIDVALIDITY.

    The read path uses EXAMINE; a mutation needs a writable session, so this
    is a separate function rather than a flag on `imap_client._select`. That
    keeps the read path incapable of writing even by mistake.
    """
    try:
        typ, _ = conn.select(encode_mailbox(mailbox), readonly=False)
        if typ != "OK":
            raise IMAPError(f"cannot select mailbox {mailbox!r}", kind="schema")
        typ, data = conn.response("UIDVALIDITY")
    except IMAPError:
        raise
    except BaseException as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if not data or not data[0]:
        raise IMAPError("server did not report UIDVALIDITY", kind="schema")
    try:
        return int(re.sub(rb"[^0-9]", b"", data[0]) or b"0")
    except ValueError:
        raise IMAPError("unparseable UIDVALIDITY", kind="schema") from None


_MESSAGE_ID_RE = re.compile(rb"message-id:\s*(?P<mid>[^\r\n]+)", re.I)


def peek_message_id(conn: Any, uid: int) -> Optional[str]:
    """Read ONE header for the UID, or None if the UID no longer resolves.

    Headers only. This module must never pull a body — a body is
    attacker-controlled text, and the write plane has no business reading
    it. `BODY.PEEK` also leaves `\\Seen` untouched, so verifying a message
    never marks it read.
    """
    try:
        typ, data = conn.uid(
            "FETCH", str(int(uid)), "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])"
        )
    except BaseException as exc:  # noqa: BLE001
        raise _classify(exc) from None
    if typ != "OK" or not data:
        return None
    for part in data:
        blob = part[1] if isinstance(part, tuple) and len(part) >= 2 else part
        if not blob:
            continue
        raw = blob if isinstance(blob, bytes) else str(blob).encode()
        found = _MESSAGE_ID_RE.search(raw)
        if found:
            return found.group("mid").decode("ascii", "replace").strip().strip("<> ")
    return None


def verify_target(
    conn: Any,
    uid: int,
    *,
    expect_message_id: Optional[str] = None,
) -> str:
    """Confirm a UID still names the message the caller meant. Refuse if not.

    Called immediately before each mutation, inside the same session and the
    same SELECT. IMAP offers no transaction, so "atomic" here rests on a
    property of the protocol rather than a lock: within one UIDVALIDITY
    epoch a UID is permanent and is NEVER reused (RFC 3501 §2.3.1.1). So a
    UID can only ever be in one of two states — still naming the same
    message, or naming nothing at all. There is no state in which it
    silently comes to name a DIFFERENT message, which is the failure a
    check-then-act race would otherwise produce.

    That leaves exactly two ways state can move under us, and both are
    refusals rather than surprises:

      * UIDVALIDITY changed  -> every UID now means something else. Caught
        by `select_writable` + the caller's expected value, before any
        mutation is issued.
      * the message vanished -> the FETCH here returns nothing, and we
        abandon instead of issuing a MOVE that would quietly affect zero
        messages and report success.

    Sequence numbers, which DO shift under a concurrent expunge, are never
    used anywhere in this module: every command is a UID command.
    """
    actual = peek_message_id(conn, uid)
    if actual is None:
        raise StateConflictError(
            f"uid {uid} is no longer in this mailbox — it was moved or "
            "deleted by someone else since you looked. Nothing was changed. "
            "Search again to get current UIDs."
        )
    if expect_message_id:
        wanted = str(expect_message_id).strip().strip("<> ")
        if wanted and wanted != actual:
            raise StateConflictError(
                f"uid {uid} now holds a different message than the one you "
                "selected. Nothing was changed."
            )
    return actual


# ---------------------------------------------------------------------------
# Moves (delete / archive / move) — one implementation, three intents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MoveRecord:
    """One moved message, recorded so the move can be reversed by hand."""

    uid: int
    message_id: str
    source_mailbox: str
    destination_mailbox: str
    source_uidvalidity: int
    destination_uid: Optional[int]
    mechanism: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "message_id": self.message_id,
            "from": self.source_mailbox,
            "to": self.destination_mailbox,
            "source_uidvalidity": self.source_uidvalidity,
            "destination_uid": self.destination_uid,
            "mechanism": self.mechanism,
        }


_COPYUID_RE = re.compile(rb"COPYUID\s+\d+\s+[\d,:]+\s+(?P<dest>[\d,:]+)", re.I)


def _destination_uid(conn: Any, data: list) -> Optional[int]:
    """Pull the new UID out of the server's COPYUID response, if it sent one.

    RFC 6851 servers report `[COPYUID <validity> <src> <dst>]` on MOVE. When
    absent we record None rather than a guess; the manifest still carries the
    Message-ID, which is how a reversal finds the message.
    """
    blobs: list[bytes] = []
    for part in data or []:
        for piece in part if isinstance(part, tuple) else (part,):
            if isinstance(piece, bytes):
                blobs.append(piece)
            elif isinstance(piece, str):
                blobs.append(piece.encode())
    try:
        typ, extra = conn.response("COPYUID")
        for piece in extra or []:
            if isinstance(piece, bytes):
                blobs.append(piece)
            elif isinstance(piece, str):
                blobs.append(piece.encode())
    except BaseException:  # noqa: BLE001 - absence is normal, never fatal
        pass
    for blob in blobs:
        found = _COPYUID_RE.search(blob)
        if found:
            tail = found.group("dest").split(b",")[-1].split(b":")[-1]
            try:
                return int(tail)
            except ValueError:
                return None
    return None


def require_move_capability(conn: Any) -> None:
    """Refuse rather than fall back to the EXPUNGE-based move.

    The classic pre-RFC-6851 move is COPY + `\\Deleted` + EXPUNGE. That is
    exactly the sequence rail 1 exists to prevent, so on a server without
    MOVE we stop and say so. A partial move that leaves the original behind
    would be worse: the caller would believe their mail was filed.
    """
    caps = tuple(str(c).upper() for c in (getattr(conn, "capabilities", ()) or ()))
    if "MOVE" not in caps:
        raise IMAPError(
            "this mail server does not support the IMAP MOVE extension "
            "(RFC 6851). Refusing to fall back to COPY + \\Deleted + "
            "EXPUNGE, which destroys mail permanently. Move these messages "
            "in your mail client instead.",
            kind="refused",
        )


def move_uids(
    conn: Any,
    *,
    uids: list[int],
    source_mailbox: str,
    destination_mailbox: str,
    expect_uidvalidity: Optional[int] = None,
    expect_message_ids: Optional[dict[int, str]] = None,
) -> list[MoveRecord]:
    """Move messages between folders. The one mutating path for delete,
    archive, and move — those differ only in which folder they target.

    Check and act share one session and one SELECT, and each UID is
    re-verified in the instant before its own MOVE rather than once for the
    whole batch, so a message that disappears midway through a batch stops
    that message instead of corrupting the rest.
    """
    if not uids:
        return []
    if len(uids) > MAX_BULK:
        raise RailViolation(
            f"refusing {len(uids)} messages in one operation; the cap is "
            f"{MAX_BULK}. This is a refusal, not a truncation — nothing was "
            "changed. Split the work into smaller batches you can check."
        )
    if source_mailbox == destination_mailbox:
        raise RailViolation(
            f"source and destination are both {source_mailbox!r}; nothing to do."
        )

    require_move_capability(conn)

    # The check and every mutation live under this one SELECT.
    uidvalidity = select_writable(conn, source_mailbox)
    if expect_uidvalidity is not None and int(expect_uidvalidity) != uidvalidity:
        raise StateConflictError(
            f"mailbox {source_mailbox!r} was renumbered (UIDVALIDITY "
            f"{expect_uidvalidity} -> {uidvalidity}); every UID you have now "
            "refers to a different message. Nothing was changed. Search "
            "again before retrying."
        )

    encoded_destination = encode_mailbox(destination_mailbox)
    records: list[MoveRecord] = []
    for uid in uids:
        uid = int(uid)
        expected = (expect_message_ids or {}).get(uid)
        try:
            # Re-verified HERE, immediately before this UID's own mutation.
            message_id = verify_target(conn, uid, expect_message_id=expected)
            _, data = _mutate(conn, "UID MOVE", str(uid), encoded_destination)
        except IMAPError as exc:
            if records:
                # Some mail has already moved. Surface both the failure AND
                # where those messages went; dropping the records here would
                # strand them with no manifest.
                raise PartialMoveError(
                    f"moved {len(records)} of {len(uids)} messages, then "
                    f"failed on uid {uid}: {exc}",
                    records,
                    kind=exc.kind,
                ) from None
            raise
        records.append(
            MoveRecord(
                uid=uid,
                message_id=message_id,
                source_mailbox=source_mailbox,
                destination_mailbox=destination_mailbox,
                source_uidvalidity=uidvalidity,
                destination_uid=_destination_uid(conn, data),
                mechanism="UID MOVE",
            )
        )
    return records


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------


def store_flags(
    conn: Any,
    *,
    uids: list[int],
    mailbox: str,
    flags: list[str],
    add: bool,
    expect_uidvalidity: Optional[int] = None,
) -> list[dict[str, Any]]:
    """Add or remove flags. `\\Deleted` is refused by `_assert_safe_flags`."""
    if not uids:
        return []
    if len(uids) > MAX_BULK:
        raise RailViolation(
            f"refusing {len(uids)} messages in one operation; the cap is "
            f"{MAX_BULK}. Nothing was changed."
        )
    checked = _assert_safe_flags(flags)
    if not checked:
        raise RailViolation("no flags given")

    uidvalidity = select_writable(conn, mailbox)
    if expect_uidvalidity is not None and int(expect_uidvalidity) != uidvalidity:
        raise StateConflictError(
            f"mailbox {mailbox!r} was renumbered (UIDVALIDITY "
            f"{expect_uidvalidity} -> {uidvalidity}). Nothing was changed."
        )

    verb = "+FLAGS" if add else "-FLAGS"
    out: list[dict[str, Any]] = []
    for uid in uids:
        uid = int(uid)
        message_id = verify_target(conn, uid)
        _mutate(conn, "UID STORE", str(uid), verb, "(" + " ".join(checked) + ")")
        out.append(
            {
                "uid": uid,
                "message_id": message_id,
                "mailbox": mailbox,
                "flags": list(checked),
                "action": "add" if add else "remove",
            }
        )
    return out


# ---------------------------------------------------------------------------
# Drafts
# ---------------------------------------------------------------------------


def build_draft(
    *,
    to: list[str],
    subject: str,
    body: str,
    cc: Optional[list[str]] = None,
    bcc: Optional[list[str]] = None,
    from_address: Optional[str] = None,
    in_reply_to: Optional[str] = None,
) -> EmailMessage:
    """Compose an RFC 5322 message for APPEND.

    Header values are set through `EmailMessage`, which refuses embedded
    newlines, so a subject cannot smuggle extra headers (a Bcc, a Reply-To)
    into the draft.
    """
    msg = EmailMessage()
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
    if from_address:
        msg["From"] = from_address
    msg["Subject"] = subject or ""
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    if in_reply_to:
        clean = str(in_reply_to).strip()
        bracketed = clean if clean.startswith("<") else f"<{clean}>"
        msg["In-Reply-To"] = bracketed
        msg["References"] = bracketed
    msg.set_content(body or "")
    return msg


def append_draft(
    conn: Any, *, mailbox: str, message: EmailMessage
) -> dict[str, Any]:
    """APPEND a draft. This is the whole of "write an email" here.

    `\\Draft` marks it as unfinished so the mail client files it correctly,
    and `\\Seen` keeps it from showing up as unread mail the user did not
    receive. There is no send: a person opens the draft and sends it.
    """
    flags = "(" + " ".join(_assert_safe_flags(["\\Draft", "\\Seen"])) + ")"
    raw = message.as_bytes()
    _, data = _mutate(
        conn,
        "APPEND",
        encode_mailbox(mailbox),
        flags,
        None,
        raw,
    )
    appended_uid = _appenduid(conn, data)
    return {
        "mailbox": mailbox,
        "uid": appended_uid,
        "message_id": str(message.get("Message-ID") or "").strip("<> "),
        "bytes": len(raw),
    }


_APPENDUID_RE = re.compile(rb"APPENDUID\s+\d+\s+(?P<uid>\d+)", re.I)


def _appenduid(conn: Any, data: list) -> Optional[int]:
    """The new draft's UID from APPENDUID, or None when unreported."""
    blobs: list[bytes] = []
    for part in data or []:
        for piece in part if isinstance(part, tuple) else (part,):
            if isinstance(piece, bytes):
                blobs.append(piece)
            elif isinstance(piece, str):
                blobs.append(piece.encode())
    try:
        _, extra = conn.response("APPENDUID")
        for piece in extra or []:
            if isinstance(piece, bytes):
                blobs.append(piece)
            elif isinstance(piece, str):
                blobs.append(piece.encode())
    except BaseException:  # noqa: BLE001
        pass
    for blob in blobs:
        found = _APPENDUID_RE.search(blob)
        if found:
            try:
                return int(found.group("uid"))
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------------------
# Undo manifest
# ---------------------------------------------------------------------------


def build_manifest(
    operation: str,
    records: list[MoveRecord],
    *,
    provider: str,
    dry_run: bool,
) -> dict[str, Any]:
    """Name every message moved and where it went.

    A move is reversible in principle — the mail is sitting in the
    destination folder — but only if someone can still find it. This is what
    makes that possible after the fact, so it carries the Message-ID as well
    as the UIDs: the destination UID is the fast path, and the Message-ID is
    the one identifier that survives a renumbering.
    """
    return {
        "operation": operation,
        "provider": provider,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "count": len(records),
        "reverse_with": (
            "imap_move_messages(uids=[<destination_uid>], "
            "mailbox=<to>, destination=<from>)"
        ),
        "moved": [r.as_dict() for r in records],
    }
