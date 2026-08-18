# icloud-mcp

iCloud Mail (IMAP) → second brain + Mycelium runtime.

Local stdio MCP server. Reads iCloud Mail, writes markdown notes into the
vault, and emits `RawItem`-shaped records the Mycelium runtime's adapter
framework consumes directly.

**Private repo.** Connectors sit inside the runtime side of the open-core
boundary, never on a public repo.

## Why local, not a hosted connector

An Apple app-specific password is unscoped: full mailbox read+write, no
refresh token, no per-scope revocation. (iCloud's IMAP greeting advertises
`AUTH=XOAUTH2`, but Apple publishes no third-party way to obtain such a
token — `AUTH=PLAIN` with an ASP is the only door open to us.) Hosting it centrally would
concentrate unscoped mailbox credentials on a server. It stays in the local
Keychain. This is a deliberate departure from the usual remote-HTTP default
for API wrappers — the deciding factor is credential custody, not transport.

## Two consumers, one core

`imap_client.py` is the only module that speaks IMAP. Two surfaces sit on it:

- **Second brain** — `icloud_sync_to_vault` writes notes under
  `External Inputs/iCloud Mail/<mailbox>/YYYY-MM-DD-<slug>.md`
- **Mycelium runtime** — `icloud_export_for_runtime` emits records matching
  `memory-runtime-pro:src/adapters/base.py::RawItem` field-for-field, so
  `src/adapters/icloud/adapter.py` wraps this instead of reimplementing it

`tests/test_normalize.py::RAW_ITEM_FIELDS` hardcodes the runtime's field list
so a drift in either repo fails here rather than at port time.

## Tools

| Tool | Access | Purpose |
|---|---|---|
| `icloud_health` | read | reachability + credential presence |
| `icloud_list_mailboxes` | read | exact folder names |
| `icloud_search_messages` | read | compact summaries, no bodies |
| `icloud_read_message` | read | one full message |
| `icloud_sync_to_vault` | **write** | notes into the vault |
| `icloud_export_for_runtime` | read | `RawItem` records |
| `icloud_explain_filter` | read | why a message was or wasn't ingested |

Seven actions, under the ~15 threshold where search+execute starts paying —
so it's one tool per action.

## Safety rails

**The mailbox is never modified.** Sessions open with `EXAMINE` (read-only)
and every fetch uses `BODY.PEEK[]`. A bare `FETCH BODY[]` sets `\Seen` as a
side effect, so a "read-only" sync would silently mark your unread mail read.
The only tool that writes anything writes *notes into the vault*.

**UIDVALIDITY is checked every incremental run.** IMAP UIDs are stable only
within a UIDVALIDITY epoch. If iCloud renumbers a mailbox, a stale cursor
points at unrelated messages and the sync skips real mail forever. On a
mismatch the cursor is discarded and the response says `uidvalidity_reset:
true` rather than quietly under-reporting.

**Email bodies are untrusted input.** Every body is wrapped in an
`UNTRUSTED_EMAIL_BODY` fence, and a body that forges the closing marker to
escape its own fence is neutralised. Message content is data to summarise,
never instructions to follow.

**The credential never surfaces.** IMAP `LOGIN` failures echo the command
line back — which contains the password — so auth errors are replaced
wholesale rather than interpolated. `keychain.mask()` shows a suffix only,
never the prefix.

**Vault root is always reported.** Every write result carries `vault_root`
and `root_source`. This is a direct lesson from the `auto-send.py` incident
where a silent default misfiled ~380 files over three months because the
happy path looked identical either way.

## Filter

Mirrors the MYC-148 smart-default contract from the Gmail adapter, mapped
onto signals IMAP actually carries:

| Gmail | iCloud |
|---|---|
| label `SENT` | mailbox `Sent Messages` |
| `replied_by_user` | `\Answered` flag |
| label `IMPORTANT` | `\Flagged` flag |
| `CATEGORY_PROMOTIONS` | `List-Unsubscribe` header |
| label `SPAM`/`TRASH` | mailbox `Junk`/`Deleted Messages` |

Precedence is the house rule: explicit block beats explicit allow, both beat
smart defaults. `icloud_explain_filter` names the exact rule that dropped a
message, so a filtered message is never indistinguishable from one that never
arrived.

## Setup

See [SETUP.md](SETUP.md). You mint the app-specific password; nothing here
creates or enters credentials on your behalf.

## Tests

```bash
uv run pytest -q
```

53 tests. The three security guards (fence escaping, path containment,
credential non-leakage) have each been mutation-tested — the guard removed,
the corresponding test confirmed failing, the guard restored.
