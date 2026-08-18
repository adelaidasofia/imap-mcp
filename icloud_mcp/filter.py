"""iCloud smart-default filter — the IMAP analogue of the Gmail one.

Mirrors the MYC-148 contract in
`memory-runtime-pro:src/adapters/gmail/filter.py`:

    keep:  sent + received-and-replied + last 12 months
    skip:  newsletters, marketing automation, automated alerts, spam

IMAP exposes none of Gmail's category labels, so each spec rule is mapped to
a signal IMAP actually carries:

    Gmail signal                 ->  IMAP signal
    label SENT                   ->  mailbox "Sent Messages"
    replied_by_user=True         ->  \\Answered flag
    label IMPORTANT              ->  \\Flagged flag
    CATEGORY_PROMOTIONS/SOCIAL   ->  List-Unsubscribe header present
    label SPAM / TRASH           ->  mailbox Junk / Deleted Messages
    automated_sender             ->  same no-reply address patterns

Precedence matches the house rule exactly: explicit block wins over explicit
allow, and both win over smart defaults. `smart_defaults_enabled=False`
degrades to allow-all-not-blocked.
"""

from __future__ import annotations

from typing import Any, Iterable

# Copied deliberately from the Gmail filter so the two stay comparable; a
# divergence here should be a conscious edit in both places.
AUTOMATED_SENDER_PATTERNS: tuple[str, ...] = (
    "noreply@",
    "no-reply@",
    "bounce@",
    "bounces@",
    "mailer-daemon@",
    "donotreply@",
    "do-not-reply@",
    "notifications@",
    "alerts@",
    "info@",
    "marketing@",
    "newsletter@",
    "support@",
)

SKIP_MAILBOXES: tuple[str, ...] = (
    "junk",
    "spam",
    "deleted messages",
    "trash",
    "bulk mail",
)

KEEP_MAILBOXES: tuple[str, ...] = (
    "sent messages",
    "sent",
)

# RFC 3834 / RFC 2919 automation markers.
_BULK_PRECEDENCE = ("bulk", "junk", "list", "auto_reply")


def _norm(text: Any) -> str:
    return str(text or "").strip().lower()


def _matches_any(haystack: str, needles: Iterable[str]) -> bool:
    return any(n and n in haystack for n in needles)


def should_ingest(
    item: dict[str, Any],
    *,
    smart_defaults_enabled: bool = True,
    extra_allow: Iterable[str] = (),
    extra_block: Iterable[str] = (),
) -> tuple[bool, str]:
    """Decide whether one normalized item is worth ingesting.

    Returns (keep, reason). The reason string is always populated so a
    filtered-out message is explainable rather than silently vanishing.
    """
    meta = item.get("metadata") or {}
    author = _norm(item.get("author"))
    mailbox = _norm(meta.get("mailbox"))
    labels = [_norm(x) for x in (item.get("labels") or [])]
    subject = _norm(item.get("title"))

    # Anything the user explicitly blocked loses immediately.
    blockables = " ".join([author, mailbox, subject])
    block_list = [_norm(x) for x in extra_block]
    if _matches_any(blockables, block_list):
        return False, "extra_block"

    allow_list = [_norm(x) for x in extra_allow]
    if _matches_any(blockables, allow_list):
        return True, "extra_allow"

    if not smart_defaults_enabled:
        return True, "smart_defaults_disabled"

    if any(mailbox == m for m in SKIP_MAILBOXES):
        return False, f"mailbox:{mailbox}"

    if any(mailbox == m for m in KEEP_MAILBOXES):
        return True, "sent_by_user"

    # \Answered — the user replied, so the thread matters to them.
    if any("answered" in lbl for lbl in labels):
        return True, "user_replied"

    if any("flagged" in lbl for lbl in labels):
        return True, "flagged"

    if _norm(meta.get("list_unsubscribe")):
        return False, "newsletter:list_unsubscribe"

    if _norm(meta.get("precedence")) in _BULK_PRECEDENCE:
        return False, "bulk_precedence"

    if _matches_any(author, AUTOMATED_SENDER_PATTERNS):
        return False, "automated_sender"

    return True, "default_keep"


def partition(
    items: list[dict[str, Any]],
    *,
    smart_defaults_enabled: bool = True,
    extra_allow: Iterable[str] = (),
    extra_block: Iterable[str] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split items into (kept, skipped). Skipped carry `_filter_reason` so a
    surface can render WHY something was dropped — a silently shrunk result
    set reads identically to an empty mailbox otherwise.
    """
    kept: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for item in items:
        ok, reason = should_ingest(
            item,
            smart_defaults_enabled=smart_defaults_enabled,
            extra_allow=extra_allow,
            extra_block=extra_block,
        )
        if ok:
            kept.append(item)
        else:
            skipped.append({**item, "_filter_reason": reason})
    return kept, skipped
