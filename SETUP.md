# icloud-mcp setup

Three steps. Step 1 is yours — minting a credential is not something an agent
should do on your behalf.

## 1. Mint an app-specific password

iCloud Mail has no OAuth and no REST API. IMAP with an Apple ID
**app-specific password** (ASP) is the only programmatic door, and Apple
requires two-factor authentication on the Apple ID before it will issue one.

1. Sign in at <https://appleid.apple.com>
2. **Sign-In and Security → App-Specific Passwords → Generate**
3. Label it `icloud-mcp`
4. Copy the value — it looks like `abcd-efgh-ijkl-mnop` and is shown once

Treat it like a root password for your mailbox: an ASP is **unscoped**. It
grants full read and write on the whole account, has no refresh token, and
cannot be narrowed. Revoke it from the same page if it ever leaks.

## 2. Store it in the Keychain

```bash
security add-generic-password -s icloud-mcp -a you@icloud.com -w
```

`security` prompts for the value, so it never lands in your shell history.
Nothing in this repo ever writes the ASP to disk, logs it, or returns it from
a tool — `keychain.mask()` renders a suffix only.

## 3. Wire the server

Add to `.mcp.json`:

```json
{
  "mcpServers": {
    "icloud": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/you/dev/icloud-mcp", "icloud-mcp"],
      "env": {
        "ICLOUD_ACCOUNT": "you@icloud.com",
        "ICLOUD_MCP_VAULT_ROOT": "/Users/you/AdelaidaNotes"
      }
    }
  }
}
```

`ICLOUD_MCP_VAULT_ROOT` is worth setting explicitly. Unset, the writer falls
back to `~/AdelaidaNotes` and *says so* in every response (`root_source:
fallback:default`) — but an explicit value is how you avoid finding out three
months later that mail landed in the wrong vault.

## 4. Verify

```bash
uv run --directory /Users/you/dev/icloud-mcp python -c "from icloud_mcp import server; print(server.icloud_health())"
```

Expected on success: `{'ok': True, 'source': 'icloud', 'latency_ms': <int>, ...}`

Failure modes, all classified rather than thrown:

| `kind` | Meaning | Fix |
|---|---|---|
| `auth` + `no_account` | `ICLOUD_ACCOUNT` unset | set it in the env block |
| `auth` + `no_password` | no ASP in the Keychain | step 2 |
| `auth` (from iCloud) | ASP rejected, or 2FA off | re-mint at appleid.apple.com |
| `transport` | network or TLS | check connectivity |
| `rate_limit` | iCloud throttled you | back off and retry |

## Non-macOS hosts

Only `keychain.py` is macOS-specific. On Linux or Windows, set
`ICLOUD_APP_SPECIFIC_PASSWORD` in the environment instead. The Keychain wins
when both are present, so an env var can never silently shadow the vault.
