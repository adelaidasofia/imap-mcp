# imap-mcp

Connect any mailbox to your second brain.

An MCP server that reads mail over IMAP — iCloud, Gmail, Outlook, Fastmail,
university or company mail, anything that speaks the protocol — and turns it
into markdown notes you can search, plus `RawItem` records the Mycelium
runtime ingests directly.

MIT licensed. Runs on macOS, Linux, and Windows.

## Why IMAP

Every mail provider speaks IMAP. One connector covers all of them, which
matters when a room full of people each bring a different mailbox.

Where a provider already has a proper OAuth connector, prefer it —
[`google-workspace-mcp`](https://github.com/adelaidasofia/google-workspace-mcp)
for Gmail, [`microsoft-365-mcp`](https://github.com/adelaidasofia/microsoft-365-mcp)
for Outlook. OAuth gives scoped, revocable access; an IMAP app password does
not. This server is for the mailboxes those two cannot reach: iCloud, which
publishes no OAuth grant for Mail at all, and every smaller or self-hosted
provider.

## Supported providers

| Provider | Host | Notes |
|---|---|---|
| `icloud` | `imap.mail.me.com` | Needs 2FA on the Apple ID |
| `gmail` | `imap.gmail.com` | Prefer the OAuth connector; needs 2-Step Verification |
| `outlook` | `outlook.office365.com` | Prefer the OAuth connector; many tenants disable IMAP |
| `fastmail` | `imap.fastmail.com` | App passwords can be scoped to IMAP only |
| `generic` | you set `IMAP_HOST` | University, company, self-hosted |

Ask the server itself with `imap_list_providers` — it returns each provider's
host and the exact page where you mint a password.

## Setup

See [SETUP.md](SETUP.md). Three steps, and you mint the password yourself.

## Tools

| Tool | Access | Purpose |
|---|---|---|
| `imap_list_providers` | read | providers + where to get a password |
| `imap_health` | read | is it reachable, does the credential work |
| `imap_list_mailboxes` | read | exact folder names |
| `imap_search_messages` | read | compact summaries, no bodies |
| `imap_read_message` | read | one full message |
| `imap_sync_to_vault` | **write** | notes into your vault |
| `imap_export_for_runtime` | read | `RawItem` records |
| `imap_explain_filter` | read | why a message was or wasn't ingested |

Eight actions, under the ~15 threshold where a search+execute surface starts
paying for itself, so it's one tool per action.

## Safety

**Your mailbox is never modified.** Sessions open with `EXAMINE` (read-only)
and every fetch uses `BODY.PEEK[]`. A plain `FETCH BODY[]` sets the `\Seen`
flag as a side effect, so a "read-only" sync would quietly mark your unread
mail as read. The only tool that writes anything writes *notes into your
vault*.

**Your password never leaves your machine.** It lives in the OS keychain, is
never written to a config file, never logged, and never returned by a tool.
IMAP `LOGIN` failures echo the failed command back — which contains the
password — so auth errors are replaced wholesale rather than passed through.

**Email is treated as untrusted input.** Every message body is wrapped in an
`UNTRUSTED_EMAIL_BODY` fence, and a body that forges the closing marker to
break out of its own fence is neutralised. Mail is data to summarise, never
instructions to follow. This matters more than it sounds: anyone can send you
an email, so an unfenced body is a stranger writing directly into your
assistant's context.

**Nothing is skipped silently.** If the server renumbers a mailbox
(`UIDVALIDITY` changed), the sync cursor is discarded and the response says
`uidvalidity_reset: true` — a stale cursor would otherwise point at unrelated
messages and skip real mail forever. Filtered messages carry the rule that
dropped them, and `imap_explain_filter` explains any single one.

**Every write says where it went.** Results carry `vault_root` and
`root_source`, so mail landing in the wrong folder is visible in the first
response rather than discovered months later.

## Filter

Smart defaults keep what matters and drop the noise. Folder names differ by
provider and by language, so they come from the provider profile rather than
being hardcoded — Gmail nests under `[Gmail]/`, Outlook says `Junk Email`, a
Spanish-locale account says `Enviados`.

| Keep | Drop |
|---|---|
| mail you sent | spam / junk / trash folders |
| threads you replied to (`\Answered`) | newsletters (`List-Unsubscribe`) |
| flagged mail (`\Flagged`) | `noreply@`-style automated senders |

Explicit block beats explicit allow; both beat smart defaults. Turn defaults
off entirely with `apply_smart_filter=False`.

## Two consumers, one core

`imap_client.py` is the only module that speaks IMAP.

- **Second brain** — `imap_sync_to_vault` writes
  `External Inputs/<Provider>/<mailbox>/YYYY-MM-DD-<slug>.md`
- **Mycelium runtime** — `imap_export_for_runtime` emits records matching the
  runtime's `RawItem` field-for-field, so the server-side adapter wraps this
  rather than reimplementing it

## Tests

```bash
uv run pytest -q
```

65 tests, no network required. The security guards (fence escaping, path
containment, credential non-leakage) have each been mutation-tested: the
guard removed, the matching test confirmed failing, the guard restored.

**Not yet verified:** no live smoke test has run against a real mailbox on
any provider. Every test uses synthetic fixtures, which proves the parsing
and filtering logic but not that a live server accepts these exact commands.
