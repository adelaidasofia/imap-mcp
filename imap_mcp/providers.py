"""Provider profiles.

IMAP is one protocol; providers differ only in endpoint, folder naming, and
how you get a password. Keeping those three things in a table — instead of
hardcoding one vendor — is what lets a 30X student connect whatever mail
they actually have.

Adding a provider is a dict entry, not a code change. `generic` covers
anything not listed (Fastmail-hosted domains, university and corporate mail,
self-hosted dovecot) by taking host and port from config.

**Every provider here uses an app-specific password, never your main
account password.** Gmail and Outlook both refuse plain IMAP passwords when
2FA is on, which is the configuration everyone should be in. Where a
provider has a real OAuth connector already (Gmail, Outlook), prefer it —
IMAP here is the fallback for accounts those connectors cannot reach.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Provider:
    """One mail provider's IMAP profile.

    Mailbox names are the load-bearing part. IMAP has no standard for what
    the Sent or Junk folder is called, so a filter that hardcodes English
    Apple names silently misclassifies every other provider — Gmail nests
    under "[Gmail]/", Outlook says "Junk Email", and a Spanish-locale
    account says "Enviados". Each profile carries its own names and the
    filter reads them from here.
    """

    slug: str
    label: str
    imap_host: Optional[str]
    imap_port: int = 993
    # No SMTP fields on purpose, and this is now load-bearing rather than
    # tidy. The write plane creates drafts by APPENDing to the Drafts folder;
    # SENDING is SMTP, a different protocol on a different port. With no SMTP
    # host anywhere in the table there is nothing for a send path to connect
    # to, so "cannot send" is structural instead of a promise. `write.py`
    # bans the verb as well, and `test_write_never_sends.py` asserts both.
    # Do not add smtp_host/smtp_port here to "round out the profile".

    # Folders whose contents should never be ingested.
    skip_mailboxes: tuple[str, ...] = ()
    # Folders that mean "the user wrote this", always worth keeping.
    sent_mailboxes: tuple[str, ...] = ()

    # Write-plane destinations. These are WIRE names carrying real casing,
    # unlike skip_/sent_mailboxes above, which are lowercase tokens the
    # filter compares case-insensitively. A MOVE or an APPEND has to name a
    # folder exactly as the server spells it, so the two cannot share a list
    # and these had to be added rather than reused.
    #
    # They are a FALLBACK, never the first answer. The server's own RFC 6154
    # SPECIAL-USE attributes (\Drafts, \Trash, \Archive) win whenever it
    # publishes them, which is what keeps a Spanish-locale mailbox
    # ("Borradores", "Papelera") working without a profile per language.
    drafts_mailboxes: tuple[str, ...] = ("Drafts",)
    trash_mailboxes: tuple[str, ...] = ("Trash",)
    archive_mailboxes: tuple[str, ...] = ("Archive",)
    # Where the user mints an app-specific password.
    password_url: str = ""
    # Short, honest note rendered in setup docs and the Connect tile.
    note: str = ""
    requires_host_config: bool = False


_COMMON_SKIP: tuple[str, ...] = ("junk", "spam", "trash", "deleted messages", "bulk mail")

PROVIDERS: dict[str, Provider] = {
    "icloud": Provider(
        slug="icloud",
        label="iCloud Mail",
        imap_host="imap.mail.me.com",
        skip_mailboxes=_COMMON_SKIP + ("archive",),
        sent_mailboxes=("sent messages",),
        drafts_mailboxes=("Drafts",),
        trash_mailboxes=("Deleted Messages", "Trash"),
        archive_mailboxes=("Archive",),
        password_url="https://appleid.apple.com",
        note="Requires two-factor authentication on the Apple ID before Apple will issue an app-specific password.",
    ),
    "gmail": Provider(
        slug="gmail",
        label="Gmail / Google Workspace (IMAP)",
        imap_host="imap.gmail.com",
        # Gmail nests special folders under "[Gmail]/". "All Mail" is skipped
        # deliberately: every message already appears in its own label, so
        # ingesting it duplicates the entire mailbox.
        skip_mailboxes=_COMMON_SKIP + ("[gmail]/spam", "[gmail]/trash", "[gmail]/all mail"),
        sent_mailboxes=("[gmail]/sent mail", "sent mail"),
        drafts_mailboxes=("[Gmail]/Drafts",),
        trash_mailboxes=("[Gmail]/Trash",),
        # Gmail archiving is "remove the Inbox label"; over IMAP the
        # closest true equivalent is a move into All Mail.
        archive_mailboxes=("[Gmail]/All Mail",),
        password_url="https://myaccount.google.com/apppasswords",
        note="Prefer the google-workspace connector, which uses OAuth. Use IMAP only for an account that connector cannot reach. Requires 2-Step Verification.",
    ),
    "outlook": Provider(
        slug="outlook",
        label="Outlook / Microsoft 365 (IMAP)",
        imap_host="outlook.office365.com",
        skip_mailboxes=_COMMON_SKIP + ("junk email", "deleted items"),
        sent_mailboxes=("sent items",),
        drafts_mailboxes=("Drafts",),
        trash_mailboxes=("Deleted Items", "Trash"),
        archive_mailboxes=("Archive",),
        password_url="https://account.microsoft.com/security",
        note="Prefer the microsoft-365 connector, which uses OAuth. Microsoft is retiring IMAP basic auth for many tenants; if login fails with no obvious cause, the tenant has disabled it.",
    ),
    "fastmail": Provider(
        slug="fastmail",
        label="Fastmail",
        imap_host="imap.fastmail.com",
        skip_mailboxes=_COMMON_SKIP,
        sent_mailboxes=("sent",),
        drafts_mailboxes=("Drafts",),
        trash_mailboxes=("Trash",),
        archive_mailboxes=("Archive",),
        password_url="https://app.fastmail.com/settings/security/apppasswords",
        note="Fastmail app passwords can be scoped to IMAP only, which is the tightest credential of any provider here.",
    ),
    "generic": Provider(
        slug="generic",
        label="Any other IMAP mailbox",
        imap_host=None,
        skip_mailboxes=_COMMON_SKIP,
        sent_mailboxes=("sent", "sent items", "sent messages", "enviados"),
        drafts_mailboxes=("Drafts", "Borradores", "Entwürfe", "Brouillons"),
        trash_mailboxes=(
            "Trash", "Deleted Messages", "Deleted Items", "Papelera", "Corbeille",
        ),
        archive_mailboxes=("Archive", "Archivo", "Archiv", "Archives"),
        password_url="",
        note="University, corporate, or self-hosted mail. Set IMAP_HOST (and IMAP_PORT if it is not 993).",
        requires_host_config=True,
    ),
}

DEFAULT_PROVIDER = "generic"


def get(slug: Optional[str]) -> Provider:
    """Resolve a provider slug.

    An unknown slug raises rather than silently falling back to `generic`:
    a typo'd provider that quietly became "generic" would then demand a host
    the user never meant to supply, and the resulting error would point at
    the wrong thing.
    """
    key = (slug or DEFAULT_PROVIDER).strip().lower()
    if key not in PROVIDERS:
        known = ", ".join(sorted(PROVIDERS))
        raise KeyError(f"unknown provider {key!r}; known providers: {known}")
    return PROVIDERS[key]


def resolve_host(provider: Provider, host_override: Optional[str]) -> str:
    """Return the IMAP host, honouring an override.

    Fails loud when a `generic` profile has no host, instead of connecting
    to a default that would belong to someone else's mail server.
    """
    host = (host_override or "").strip() or provider.imap_host
    if not host:
        raise ValueError(
            f"provider {provider.slug!r} needs an explicit IMAP host; "
            "set IMAP_HOST in the server env"
        )
    return host


def listing() -> list[dict[str, object]]:
    """Provider table for the `imap_list_providers` tool and setup docs."""
    return [
        {
            "slug": p.slug,
            "label": p.label,
            "imap_host": p.imap_host,
            "imap_port": p.imap_port,
            "password_url": p.password_url,
            "requires_host_config": p.requires_host_config,
            "note": p.note,
        }
        for p in PROVIDERS.values()
    ]
