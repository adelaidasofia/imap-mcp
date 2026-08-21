"""A recording fake IMAP server.

Every command is appended to `commands` verbatim, which is what lets the
write-plane tests assert the interesting thing: not just that an operation
returned the right value, but that certain commands were NEVER SENT. A test
that only checks return values cannot tell "refused to expunge" apart from
"expunged and then reported failure".

`after_fetch` is the interleaving hook. It fires immediately after a
verification FETCH returns, which is precisely the check-to-act gap, so a
test can have a "concurrent client" move state underneath the write plane
at the only moment where it would matter.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Optional

# Folder layouts. The three cover the three ways a Trash folder gets found.
SPECIAL_USE_FOLDERS = [
    ("INBOX", "\\HasNoChildren"),
    ("Drafts", "\\HasNoChildren \\Drafts"),
    ("Deleted Messages", "\\HasNoChildren \\Trash"),
    ("Archive", "\\HasNoChildren \\Archive"),
    ("Sent Messages", "\\HasNoChildren \\Sent"),
]

# A server that publishes no SPECIAL-USE attributes: the provider profile
# has to carry it. iCloud names its trash "Deleted Messages".
PROFILE_ONLY_FOLDERS = [
    ("INBOX", "\\HasNoChildren"),
    ("Drafts", "\\HasNoChildren"),
    ("Deleted Messages", "\\HasNoChildren"),
    ("Archive", "\\HasNoChildren"),
]

# A Spanish-locale mailbox. No English name appears anywhere, so ONLY the
# SPECIAL-USE attributes can resolve these — this is the layout that a
# hardcoded table of English folder names silently fails on.
SPANISH_FOLDERS = [
    ("INBOX", "\\HasNoChildren"),
    ("Borradores", "\\HasNoChildren \\Drafts"),
    ("Papelera", "\\HasNoChildren \\Trash"),
    ("Archivo", "\\HasNoChildren \\Archive"),
]

MUTATING_VERBS = ("MOVE", "STORE", "COPY", "APPEND", "EXPUNGE", "DELETE", "CREATE")


class FakeIMAP:
    def __init__(
        self,
        *,
        folders: Optional[list] = None,
        messages: Optional[dict] = None,
        capabilities: tuple = ("IMAP4REV1", "MOVE", "UIDPLUS"),
        uidvalidity: int = 42,
        after_fetch: Optional[Callable[["FakeIMAP"], None]] = None,
        raw_messages: Optional[dict] = None,
    ) -> None:
        self.commands: list[str] = []
        self.capabilities = tuple(capabilities)
        self.uidvalidity = uidvalidity
        self.messages: dict[int, str] = dict(
            messages
            if messages is not None
            else {101: "one@example.com", 102: "two@example.com"}
        )
        self.folders = list(folders if folders is not None else SPECIAL_USE_FOLDERS)
        # Full RFC 5322 bytes per UID, served only for a full-body FETCH.
        # The write plane never asks for these; the read path does.
        self.raw_messages: dict[int, bytes] = dict(raw_messages or {})
        self.selected: Optional[str] = None
        self.selected_readonly: Optional[bool] = None
        self.appended: list[dict[str, Any]] = []
        self.moved: list[tuple[int, str]] = []
        self.flag_changes: list[tuple[int, str, str]] = []
        self.after_fetch = after_fetch
        self._copyuid: Optional[bytes] = None
        self._appenduid: Optional[bytes] = None
        self._next_uid = 900

    # -- introspection helpers used by the tests --------------------------

    def mutating_commands(self) -> list[str]:
        """Every command that could have changed the mailbox."""
        return [
            c
            for c in self.commands
            if any(v in c.upper().split() or c.upper().startswith(v) for v in MUTATING_VERBS)
            or any(f" {v} " in f" {c.upper()} " for v in MUTATING_VERBS)
        ]

    def issued(self, needle: str) -> bool:
        return any(needle.upper() in c.upper() for c in self.commands)

    # -- the protocol surface ---------------------------------------------

    def login(self, account, password):
        self.commands.append("LOGIN")
        return "OK", [b"logged in"]

    def shutdown(self):
        self.commands.append("SHUTDOWN")

    def list(self):
        self.commands.append("LIST")
        return "OK", [f'({flags}) "/" "{name}"'.encode() for name, flags in self.folders]

    def select(self, mailbox, readonly=False):
        self.commands.append(f"{'EXAMINE' if readonly else 'SELECT'} {mailbox}")
        self.selected = mailbox
        self.selected_readonly = readonly
        return "OK", [b"1"]

    def response(self, code):
        if code == "UIDVALIDITY":
            return "OK", [str(self.uidvalidity).encode()]
        if code == "COPYUID":
            return "OK", [self._copyuid]
        if code == "APPENDUID":
            return "OK", [self._appenduid]
        return "OK", [None]

    def uid(self, command, *args):
        self.commands.append(("UID " + command + " " + " ".join(str(a) for a in args)).strip())
        verb = command.upper()
        if verb == "FETCH":
            return self._fetch(args)
        if verb == "MOVE":
            return self._move(args)
        if verb == "STORE":
            return self._store(args)
        if verb == "COPY":
            return "OK", [b"copied"]
        if verb == "SEARCH":
            return "OK", [" ".join(str(u) for u in sorted(self.messages)).encode()]
        return "OK", [None]

    def _uid_arg(self, args) -> Optional[int]:
        try:
            return int(str(args[0]))
        except (IndexError, ValueError):
            return None

    def _fetch(self, args):
        uid = self._uid_arg(args)
        spec = " ".join(str(a) for a in args[1:]).upper()
        wants_whole_body = "BODY.PEEK[]" in spec.replace(" ", "")
        if uid is None or uid not in self.messages:
            result = ("OK", [None])
        elif wants_whole_body:
            raw = self.raw_messages.get(uid, b"")
            result = ("OK", [(b"1 (UID %d BODY[]" % uid, raw), b")"])
        else:
            header = f"Message-ID: <{self.messages[uid]}>\r\n\r\n".encode()
            result = ("OK", [(b"1 (UID %d BODY[HEADER.FIELDS (MESSAGE-ID)]" % uid, header), b")"])
        # The check-to-act gap. A concurrent client acts HERE or nowhere.
        if self.after_fetch is not None:
            self.after_fetch(self)
        return result

    def _move(self, args):
        uid = self._uid_arg(args)
        destination = str(args[1]) if len(args) > 1 else ""
        if uid is None or uid not in self.messages:
            return "NO", [b"no such message"]
        self.messages.pop(uid)
        self.moved.append((uid, destination))
        self._next_uid += 1
        self._copyuid = f"COPYUID {self.uidvalidity} {uid} {self._next_uid}".encode()
        return "OK", [self._copyuid]

    def _store(self, args):
        uid = self._uid_arg(args)
        if uid is None or uid not in self.messages:
            return "NO", [b"no such message"]
        self.flag_changes.append(
            (uid, str(args[1]) if len(args) > 1 else "", str(args[2]) if len(args) > 2 else "")
        )
        return "OK", [b"stored"]

    def append(self, mailbox, flags, date_time, message):
        self.commands.append(f"APPEND {mailbox} {flags}")
        self._next_uid += 1
        self.appended.append(
            {"mailbox": str(mailbox), "flags": str(flags), "message": message}
        )
        self._appenduid = f"APPENDUID {self.uidvalidity} {self._next_uid}".encode()
        return "OK", [self._appenduid]

    def expunge(self):  # pragma: no cover - must never be reached
        self.commands.append("EXPUNGE")
        raise AssertionError("the write plane issued EXPUNGE")

    def close(self):
        self.commands.append("CLOSE")

    def logout(self):
        self.commands.append("LOGOUT")


def install(monkeypatch, fake: FakeIMAP, *, provider: str = "icloud") -> None:
    """Point the server's session machinery at the fake, with credentials."""
    from imap_mcp import keychain, server

    monkeypatch.setenv(server.ENV_PROVIDER, provider)
    monkeypatch.delenv(server.ENV_HOST, raising=False)
    monkeypatch.setenv(keychain._ENV_ACCOUNT, "me@example.com")
    monkeypatch.setattr(keychain, "_read", lambda s, a: "app-specific-password")
    monkeypatch.setattr(
        keychain, "get_app_specific_password", lambda account: "app-specific-password"
    )
    monkeypatch.setattr(
        keychain,
        "credential_status",
        lambda: {"configured": True, "account": "me@example.com"},
    )

    @contextmanager
    def _fake_connect(account, password, *, host, port=993, timeout=30):
        yield fake

    monkeypatch.setattr(server.imap_client, "connect", _fake_connect)
