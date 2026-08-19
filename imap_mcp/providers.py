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

from dataclasses import dataclass, field
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
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    # Folders whose contents should never be ingested.
    skip_mailboxes: tuple[str, ...] = ()
    # Folders that mean "the user wrote this", always worth keeping.
    sent_mailboxes: tuple[str, ...] = ()
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
        smtp_host="smtp.mail.me.com",
        skip_mailboxes=_COMMON_SKIP + ("archive",),
        sent_mailboxes=("sent messages",),
        password_url="https://appleid.apple.com",
        note="Requires two-factor authentication on the Apple ID before Apple will issue an app-specific password.",
    ),
    "gmail": Provider(
        slug="gmail",
        label="Gmail / Google Workspace (IMAP)",
        imap_host="imap.gmail.com",
        smtp_host="smtp.gmail.com",
        # Gmail nests special folders under "[Gmail]/". "All Mail" is skipped
        # deliberately: every message already appears in its own label, so
        # ingesting it duplicates the entire mailbox.
        skip_mailboxes=_COMMON_SKIP + ("[gmail]/spam", "[gmail]/trash", "[gmail]/all mail"),
        sent_mailboxes=("[gmail]/sent mail", "sent mail"),
        password_url="https://myaccount.google.com/apppasswords",
        note="Prefer the google-workspace connector, which uses OAuth. Use IMAP only for an account that connector cannot reach. Requires 2-Step Verification.",
    ),
    "outlook": Provider(
        slug="outlook",
        label="Outlook / Microsoft 365 (IMAP)",
        imap_host="outlook.office365.com",
        smtp_host="smtp.office365.com",
        skip_mailboxes=_COMMON_SKIP + ("junk email", "deleted items"),
        sent_mailboxes=("sent items",),
        password_url="https://account.microsoft.com/security",
        note="Prefer the microsoft-365 connector, which uses OAuth. Microsoft is retiring IMAP basic auth for many tenants; if login fails with no obvious cause, the tenant has disabled it.",
    ),
    "fastmail": Provider(
        slug="fastmail",
        label="Fastmail",
        imap_host="imap.fastmail.com",
        smtp_host="smtp.fastmail.com",
        skip_mailboxes=_COMMON_SKIP,
        sent_mailboxes=("sent",),
        password_url="https://app.fastmail.com/settings/security/apppasswords",
        note="Fastmail app passwords can be scoped to IMAP only, which is the tightest credential of any provider here.",
    ),
    "generic": Provider(
        slug="generic",
        label="Any other IMAP mailbox",
        imap_host=None,
        smtp_host=None,
        skip_mailboxes=_COMMON_SKIP,
        sent_mailboxes=("sent", "sent items", "sent messages", "enviados"),
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
