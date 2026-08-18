"""Smart-default filter tests, including the precedence rules."""

from __future__ import annotations

from icloud_mcp import filter as f


def item(**over):
    base = {
        "title": "Hello",
        "author": "person@example.com",
        "labels": ["INBOX"],
        "metadata": {"mailbox": "INBOX"},
    }
    meta = {**base["metadata"], **over.pop("metadata", {})}
    return {**base, **over, "metadata": meta}


def test_ordinary_human_mail_is_kept():
    keep, reason = f.should_ingest(item())
    assert keep and reason == "default_keep"


def test_newsletter_is_skipped():
    keep, reason = f.should_ingest(
        item(metadata={"list_unsubscribe": "<https://x/u>"})
    )
    assert not keep and reason == "newsletter:list_unsubscribe"


def test_automated_sender_is_skipped():
    keep, reason = f.should_ingest(item(author="no-reply@stripe.com"))
    assert not keep and reason == "automated_sender"


def test_junk_mailbox_is_skipped():
    keep, reason = f.should_ingest(item(metadata={"mailbox": "Junk"}))
    assert not keep and reason.startswith("mailbox:")


def test_sent_mailbox_is_kept():
    keep, reason = f.should_ingest(item(metadata={"mailbox": "Sent Messages"}))
    assert keep and reason == "sent_by_user"


def test_answered_flag_keeps_even_an_automated_sender():
    """\\Answered is the IMAP stand-in for 'the user replied' — it must
    outrank the automated-sender heuristic, or a real thread with a
    notifications@ address silently disappears."""
    keep, reason = f.should_ingest(
        item(author="notifications@github.com", labels=["INBOX", "\\Answered"])
    )
    assert keep and reason == "user_replied"


def test_explicit_block_beats_explicit_allow():
    keep, reason = f.should_ingest(
        item(author="nelly@example.com"),
        extra_allow=["nelly@example.com"],
        extra_block=["nelly@example.com"],
    )
    assert not keep and reason == "extra_block"


def test_allow_overrides_smart_default_skip():
    keep, reason = f.should_ingest(
        item(author="newsletter@substack.com"), extra_allow=["substack.com"]
    )
    assert keep and reason == "extra_allow"


def test_smart_defaults_disabled_keeps_a_newsletter():
    keep, reason = f.should_ingest(
        item(metadata={"list_unsubscribe": "<https://x/u>"}),
        smart_defaults_enabled=False,
    )
    assert keep and reason == "smart_defaults_disabled"


def test_smart_defaults_disabled_still_honours_block():
    keep, reason = f.should_ingest(
        item(author="spam@x.com"),
        smart_defaults_enabled=False,
        extra_block=["spam@x.com"],
    )
    assert not keep and reason == "extra_block"


def test_partition_reports_reasons():
    kept, skipped = f.partition(
        [item(), item(author="noreply@x.com"), item(metadata={"mailbox": "Junk"})]
    )
    assert len(kept) == 1
    assert len(skipped) == 2
    assert all("_filter_reason" in s for s in skipped)
