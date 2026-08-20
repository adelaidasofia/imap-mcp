# Setup

## The fast way: paste this to Claude

Copy this whole block into Claude Code and it will walk you through the rest,
asking only for what it cannot find on its own:

```
Set up imap-mcp for my email.

1. Clone https://github.com/adelaidasofia/imap-mcp into ~/.claude/imap-mcp
2. Ask me which email I want to connect, then tell me exactly where to make
   an app password for that provider and wait for me to make it.
3. Walk me through storing that password in my OS keychain. Never ask me to
   paste the password into a chat message or a config file.
4. Add the server to my MCP config with the right IMAP_PROVIDER for my email
   and my vault folder as IMAP_MCP_VAULT_ROOT.
5. Run imap_health and show me the result. If it fails, read the error kind
   and fix the actual cause instead of guessing.
```

Everything below is the same thing by hand, if you would rather see the parts.

---

# Setup by hand

Three steps. The first is yours, because minting a credential is not
something software should do on your behalf.

## 1. Find your provider

Ask the server:

```
imap_list_providers
```

It returns every provider it knows, the IMAP host, and the exact page where
you create a password. If your mail is not listed, use `generic` and set
`IMAP_HOST` — university and company mail almost always works this way.

## 2. Make an app password

**Do not use your normal email password.** Every provider below issues a
separate password just for apps like this one, and most require two-factor
authentication turned on first.

| Provider | Where |
|---|---|
| iCloud | appleid.apple.com → Sign-In and Security → App-Specific Passwords |
| Gmail | myaccount.google.com/apppasswords |
| Outlook | account.microsoft.com/security |
| Fastmail | Settings → Privacy & Security → App passwords (scope it to IMAP) |
| Other | search your provider's help for "app password" or "IMAP password" |

Then store it in your keychain. The command prompts for the value, so it
never lands in your shell history:

**macOS**
```bash
security add-generic-password -s imap-mcp -a you@example.com -w
```

**Linux / Windows**

Set `IMAP_APP_PASSWORD` in the server's environment instead. On macOS the
keychain always wins over the environment, so an env var can never silently
shadow it.

Treat this password like the key to your mailbox. At most providers it is
unscoped: full read and write on the whole account, with no expiry. Revoke
it from the same page if it ever leaks. Fastmail is the exception — its app
passwords can be limited to IMAP only, which is the tightest option here.

## 3. Wire the server

```json
{
  "mcpServers": {
    "imap": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/imap-mcp", "imap-mcp"],
      "env": {
        "IMAP_ACCOUNT": "you@example.com",
        "IMAP_PROVIDER": "icloud",
        "IMAP_MCP_VAULT_ROOT": "/path/to/your/vault"
      }
    }
  }
}
```

For `generic`, add `"IMAP_HOST": "mail.your-provider.com"`.

Set `IMAP_MCP_VAULT_ROOT` explicitly. Left unset it falls back to `~/Notes`
and says so in every response (`root_source: fallback:default`), but naming
it is how you avoid finding out later that mail went somewhere unexpected.

## 4. Check it works

```
imap_health
```

Success looks like `{"ok": true, "latency_ms": <number>, ...}`.

Every failure is classified rather than thrown:

| `kind` | Meaning | Fix |
|---|---|---|
| `schema` | provider unknown, or `generic` with no host | check `IMAP_PROVIDER` / set `IMAP_HOST` |
| `auth` + `no_account` | `IMAP_ACCOUNT` not set | add it to the env block |
| `auth` + `no_password` | nothing in the keychain | step 2 |
| `auth` (from the server) | password rejected, or 2FA off | re-mint it |
| `transport` | network, TLS, or wrong host | check the host and your connection |
| `rate_limit` | the provider throttled you | wait and retry |

Then try `imap_list_mailboxes` to see your folders, and
`imap_sync_to_vault` with `dry_run=True` to see exactly which notes would be
written before anything is.

## A note on Outlook

Microsoft has been switching off IMAP basic authentication for many
tenants. If your password is definitely right and login still fails, the
tenant has probably disabled IMAP — use the `microsoft-365` connector, which
uses OAuth, instead.
