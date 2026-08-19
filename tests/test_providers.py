"""Provider-profile tests.

The mailbox-name tables are the load-bearing part: a filter using Apple's
English folder names against a Gmail or Spanish-locale account
misclassifies silently, which is the worst failure mode here.
"""

from __future__ import annotations

import pytest

from imap_mcp import filter as f
from imap_mcp import providers


def test_every_profile_is_self_consistent():
    for slug, p in providers.PROVIDERS.items():
        assert p.slug == slug
        assert p.label
        assert p.imap_port > 0
        # A profile either knows its host or declares that it needs one.
        assert bool(p.imap_host) != bool(p.requires_host_config)


def test_unknown_provider_raises_rather_than_defaulting():
    with pytest.raises(KeyError) as exc:
        providers.get("nope")
    assert "known providers" in str(exc.value)


def test_generic_without_host_raises():
    with pytest.raises(ValueError):
        providers.resolve_host(providers.get("generic"), None)


def test_host_override_wins():
    assert providers.resolve_host(providers.get("icloud"), "mail.example.com") == "mail.example.com"
    assert providers.resolve_host(providers.get("icloud"), None) == "imap.mail.me.com"


def _item(mailbox: str):
    return {
        "title": "x",
        "author": "person@example.com",
        "labels": [mailbox],
        "metadata": {"mailbox": mailbox},
    }


def test_gmail_all_mail_is_skipped_but_icloud_has_no_such_folder():
    """Gmail's All Mail duplicates the entire mailbox; iCloud has no
    equivalent, so the rule must be per-provider, not global."""
    gmail = providers.get("gmail")
    keep, reason = f.should_ingest(_item("[Gmail]/All Mail"), provider=gmail)
    assert not keep and reason.startswith("mailbox:")

    icloud = providers.get("icloud")
    keep, _ = f.should_ingest(_item("[Gmail]/All Mail"), provider=icloud)
    assert keep


def test_sent_folder_name_is_provider_specific():
    cases = [
        ("icloud", "Sent Messages"),
        ("gmail", "[Gmail]/Sent Mail"),
        ("outlook", "Sent Items"),
        ("fastmail", "Sent"),
    ]
    for slug, folder in cases:
        keep, reason = f.should_ingest(_item(folder), provider=providers.get(slug))
        assert keep and reason == "sent_by_user", (slug, folder, reason)


def test_outlook_junk_email_is_skipped():
    """Outlook says 'Junk Email', not 'Junk' — an Apple-name-only table
    would ingest the whole spam folder."""
    keep, reason = f.should_ingest(_item("Junk Email"), provider=providers.get("outlook"))
    assert not keep and reason.startswith("mailbox:")


def test_generic_profile_handles_a_spanish_sent_folder():
    keep, reason = f.should_ingest(_item("Enviados"), provider=providers.get("generic"))
    assert keep and reason == "sent_by_user"


def test_filter_without_a_provider_still_uses_safe_fallbacks():
    keep, reason = f.should_ingest(_item("Junk"), provider=None)
    assert not keep and reason.startswith("mailbox:")


def test_listing_exposes_password_urls_for_real_providers():
    rows = {r["slug"]: r for r in providers.listing()}
    for slug in ("icloud", "gmail", "outlook", "fastmail"):
        assert rows[slug]["password_url"].startswith("https://"), slug
    assert rows["generic"]["requires_host_config"] is True
