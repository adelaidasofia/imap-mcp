"""macOS Keychain wrapper for icloud-mcp secrets.

One surface stored here:

    - ICLOUD_APP_SPECIFIC_PASSWORD
        service="icloud-mcp", account=<apple-id email>

iCloud Mail has NO OAuth and NO REST API. IMAP + an Apple ID app-specific
password (ASP) is the only programmatic door, and an ASP is UNSCOPED: it
grants full mailbox read+write, carries no refresh token, and cannot be
narrowed per-scope. That is exactly why it stays in the local Keychain and
never in a `.env`, a `.mcp.json` env block, or a hosted multi-tenant store.

Mint one at appleid.apple.com (requires 2FA on the Apple ID), then:

    security add-generic-password -s icloud-mcp -a you@icloud.com -w

`security` prompts for the value so it never lands in shell history.

Multi-line values are auto hex-encoded by `security`; we decode with the
same rule as the canonical house pattern (spend-mcp / stripe-mcp).

Pure stdlib + subprocess; no third-party deps. Returns ``None`` when the
key is missing rather than raising — caller decides whether the absence is
a red blocker or a yellow degradation.
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional

SERVICE = "icloud-mcp"

# Env override exists for CI and for non-macOS hosts (the IMAP core itself is
# cross-platform per the Mycelium cross-platform rule; only the Keychain read
# is macOS-specific). Keychain WINS when both are present: an env var is the
# weaker custody surface, so it must never silently shadow the vault.
_ENV_PASSWORD = "ICLOUD_APP_SPECIFIC_PASSWORD"
_ENV_ACCOUNT = "ICLOUD_ACCOUNT"


def _looks_hex_encoded(value: str) -> bool:
    """`security` hex-encodes values it considers non-plain-text.

    Guarded tightly: an ASP is 16 lowercase letters in `xxxx-xxxx-xxxx-xxxx`
    form, which contains '-' and so can never satisfy this predicate. Without
    the length floor a short all-hex password would be silently mangled.
    """
    if len(value) < 32 or len(value) % 2 != 0:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def _read(service: str, account: str) -> Optional[str]:
    """Run ``security find-generic-password`` and return the password text.

    Returns None on miss; never raises (callers handle the absence).
    """
    try:
        proc = subprocess.run(
            ["security", "find-generic-password", "-a", account, "-s", service, "-w"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # FileNotFoundError => not macOS (no `security` binary). Not an error.
        return None
    if proc.returncode != 0:
        return None
    value = (proc.stdout or "").strip()
    if not value:
        return None
    if _looks_hex_encoded(value):
        try:
            return bytes.fromhex(value).decode("utf-8").strip()
        except (ValueError, UnicodeDecodeError):
            return value
    return value


def get_account() -> Optional[str]:
    """Return the configured iCloud address (the IMAP username).

    Read from env only — this is an identifier, not a secret.
    """
    value = (os.environ.get(_ENV_ACCOUNT) or "").strip()
    return value or None


def get_app_specific_password(account: str) -> Optional[str]:
    """Return the ASP for `account`, or None if absent.

    Keychain first, env fallback. Never logged, never returned in a tool
    payload, never included in an error message.
    """
    value = _read(SERVICE, account)
    if value:
        return value
    env_value = (os.environ.get(_ENV_PASSWORD) or "").strip()
    return env_value or None


def mask(secret: Optional[str]) -> str:
    """Render a secret safe for logs and health payloads.

    Shows only a length-bucketed suffix; never the full value, and never the
    prefix (an ASP's first group is as identifying as its last).
    """
    if not secret:
        return "<absent>"
    if len(secret) <= 4:
        return "*" * len(secret)
    return f"{'*' * (len(secret) - 4)}{secret[-4:]}"


def credential_status(account: Optional[str] = None) -> dict[str, object]:
    """Non-throwing credential probe for the health tool.

    Returns presence + a masked suffix ONLY. Distinguishes the three real
    states so a missing credential never reads as a working one:
    `no_account` / `no_password` / `present`.
    """
    resolved = account or get_account()
    if not resolved:
        return {"configured": False, "reason": "no_account", "account": None}
    secret = get_app_specific_password(resolved)
    if not secret:
        return {"configured": False, "reason": "no_password", "account": resolved}
    return {
        "configured": True,
        "reason": "present",
        "account": resolved,
        "password_masked": mask(secret),
    }
