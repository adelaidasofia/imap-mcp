"""Second-brain writer: RawItem dicts -> markdown notes in the vault.

Vault-root resolution is EXPLICIT and always reported back to the caller.
This is a direct lesson from the `auto-send.py` incident (2026-07-31): that
script defaulted its vault root to the personal vault when the env var was
unset, so ~380 files misfiled silently across three months because the
happy path looked identical either way. Here, every write result carries
`vault_root` and `root_source`, so a wrong destination is visible in the
first response instead of discovered a quarter later.

Writes are idempotent: a note whose stored `body_sha256` matches the
incoming one is left untouched and reported as `unchanged`.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ENV_VAULT_ROOT = "ICLOUD_MCP_VAULT_ROOT"
FALLBACK_VAULT_ROOT = Path.home() / "AdelaidaNotes"

_SHA_RE = re.compile(r"^body_sha256:\s*([0-9a-f]{64})\s*$", re.MULTILINE)


def resolve_vault_root() -> tuple[Path, str]:
    """Return (root, how_it_was_resolved). Never guesses in silence."""
    env = (os.environ.get(ENV_VAULT_ROOT) or "").strip()
    if env:
        return Path(env).expanduser(), "env:" + ENV_VAULT_ROOT
    return FALLBACK_VAULT_ROOT, "fallback:default"


def _yaml_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\n", " ").replace("\r", " ")
    return f'"{text}"'


def render_note(item: dict[str, Any]) -> str:
    """Render one RawItem dict as a markdown note with YAML frontmatter."""
    meta = item.get("metadata") or {}
    created = item.get("created_at")
    created_iso = (
        created.astimezone(timezone.utc).isoformat()
        if isinstance(created, datetime)
        else str(created or "")
    )
    labels = item.get("labels") or []
    attachments = meta.get("attachments") or []

    lines = [
        "---",
        "type: email",
        "source: icloud",
        f"source_id: {_yaml_escape(item.get('source_id'))}",
        f"title: {_yaml_escape(item.get('title'))}",
        f"author: {_yaml_escape(item.get('author'))}",
        f"to: {_yaml_escape(meta.get('to'))}",
        f"date: {_yaml_escape(created_iso)}",
        f"mailbox: {_yaml_escape(meta.get('mailbox'))}",
        f"labels: [{', '.join(_yaml_escape(x) for x in labels)}]",
        f"has_attachments: {str(bool(meta.get('has_attachments'))).lower()}",
        f"body_sha256: {meta.get('body_sha256', '')}",
        "content_is_untrusted: true",
        "---",
        "",
        f"# {item.get('title') or '(no subject)'}",
        "",
        f"**From:** {item.get('author') or '(unknown)'}  ",
        f"**Date:** {created_iso}  ",
        f"**Mailbox:** {meta.get('mailbox') or ''}",
        "",
    ]
    if attachments:
        lines.append("**Attachments:** " + ", ".join(
            f"`{a.get('filename')}` ({a.get('content_type')})" for a in attachments
        ))
        lines.append("")
    lines.append(str(item.get("body") or ""))
    lines.append("")
    return "\n".join(lines)


def write_item(
    item: dict[str, Any], *, vault_root: Optional[Path] = None, dry_run: bool = False
) -> dict[str, Any]:
    """Write one item. Returns a per-item result dict, never raises on a
    single-file failure — the caller aggregates and reports partials.
    """
    root, root_source = (vault_root, "explicit") if vault_root else resolve_vault_root()
    rel = str(item.get("relative_path") or "").lstrip("/")
    if not rel:
        return {"status": "error", "reason": "no relative_path", "path": None}

    target = (root / rel).resolve()
    try:
        # Containment check: a crafted subject must not escape the vault via
        # traversal. `relative_path` is built from a slug so this should be
        # unreachable — which is exactly when a guard is worth having.
        target.relative_to(root.resolve())
    except ValueError:
        return {"status": "error", "reason": "path_escapes_vault", "path": str(target)}

    body = render_note(item)
    incoming_sha = str((item.get("metadata") or {}).get("body_sha256") or "")

    if target.exists():
        try:
            existing = target.read_text(encoding="utf-8")
            found = _SHA_RE.search(existing)
            if found and incoming_sha and found.group(1) == incoming_sha:
                return {
                    "status": "unchanged",
                    "path": str(target),
                    "vault_root": str(root),
                    "root_source": root_source,
                }
        except OSError:
            pass

    if dry_run:
        return {
            "status": "would_write",
            "path": str(target),
            "vault_root": str(root),
            "root_source": root_source,
        }

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, target)  # atomic
    except OSError as exc:
        return {"status": "error", "reason": str(exc), "path": str(target)}

    return {
        "status": "written",
        "path": str(target),
        "vault_root": str(root),
        "root_source": root_source,
    }


def write_items(
    items: list[dict[str, Any]],
    *,
    vault_root: Optional[Path] = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Write many items and summarise. Partial failures are reported, not
    swallowed — a run that wrote 3 of 10 must never read as success.
    """
    root, root_source = (vault_root, "explicit") if vault_root else resolve_vault_root()
    results = [write_item(i, vault_root=root, dry_run=dry_run) for i in items]
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {
        "vault_root": str(root),
        "root_source": root_source,
        "total": len(results),
        "counts": counts,
        "errors": [r for r in results if r["status"] == "error"],
        "paths": [r["path"] for r in results if r.get("status") in ("written", "would_write")],
    }


def load_checkpoint(mailbox: str, *, vault_root: Optional[Path] = None) -> Optional[dict]:
    """Read the persisted IMAP cursor for a mailbox."""
    root, _ = (vault_root, "explicit") if vault_root else resolve_vault_root()
    path = root / ".icloud-mcp" / "checkpoints.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        value = data.get(mailbox)
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def save_checkpoint(
    mailbox: str, checkpoint: dict, *, vault_root: Optional[Path] = None
) -> None:
    """Persist the IMAP cursor. Best-effort: a checkpoint write failure must
    not lose already-written notes, it only costs a re-scan next run.
    """
    root, _ = (vault_root, "explicit") if vault_root else resolve_vault_root()
    path = root / ".icloud-mcp" / "checkpoints.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, json.JSONDecodeError):
            data = {}
        data[mailbox] = checkpoint
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return
