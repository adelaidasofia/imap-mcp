# imap-mcp

Connect any mailbox to your second brain.

An MCP server that reads mail over IMAP — iCloud, Gmail, Outlook, Fastmail,
university or company mail, anything that speaks the protocol — and turns it
into markdown notes you can search, plus `RawItem` records the Mycelium
runtime ingests directly.

It can also write drafts and manage your mailbox, but only if you turn that
on. Out of the box it cannot change your mail at all.

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

Installed and left alone, the server has eight tools and none of them can
change your mailbox:

| Tool | Access | Purpose |
|---|---|---|
| `imap_list_providers` | read | providers + where to get a password |
| `imap_health` | read | is it reachable, does the credential work |
| `imap_list_mailboxes` | read | exact folder names |
| `imap_search_messages` | read | compact summaries, no bodies |
| `imap_read_message` | read | one full message |
| `imap_sync_to_vault` | writes your vault | notes into your vault |
| `imap_export_for_runtime` | read | `RawItem` records |
| `imap_explain_filter` | read | why a message was or wasn't ingested |

Set `IMAP_MCP_ENABLE_WRITES=1` and six more appear:

| Tool | Access | Purpose |
|---|---|---|
| `imap_create_draft` | writes mailbox | compose a draft. Never sends |
| `imap_update_draft` | moves mail | replace a draft with a new version |
| `imap_delete_messages` | moves mail | move to Trash. Never expunges |
| `imap_archive_messages` | moves mail | move to Archive |
| `imap_move_messages` | moves mail | move to a folder you name |
| `imap_mark_messages` | writes mailbox | read / unread / flagged / answered |

Fourteen actions, under the ~15 threshold where a search+execute surface
starts paying for itself, so it's one tool per action.

## The write plane

Turning on writes is a separate decision from connecting your mail, and the
mechanism is absence rather than permission. Without the flag the six tools
above are never registered: they don't appear in the tool list, so nothing
can call them and nothing can be talked into calling them. Read your mail
first, decide later whether you want it managed.

That split exists because an IMAP app password is not scoped. Unlike an
OAuth connector, where you can grant read and withhold write, the password
you minted already allows everything — so the restraint has to live in the
software, and it has to be structural rather than a rule the software
promises to follow.

**Deleting never destroys.** Delete means move to Trash. The server cannot
issue `EXPUNGE`, and it cannot set the `\Deleted` flag either — which
matters more than it sounds, because IMAP's `CLOSE` implicitly expunges
`\Deleted` messages when a session ends. Banning only the command would
have left the teardown able to destroy mail that something else had flagged.
Banning the flag as well means there is nothing to expunge.

**Drafts are never sent.** A draft is an `APPEND` into your Drafts folder.
Sending is SMTP, a different protocol on a different port, and there is no
SMTP host anywhere in this package — nothing for a send path to connect to
even if someone wrote one. You open the draft in your own mail client and
decide whether to send it.

**Nothing in an email can trigger any of this.** This is the reason the
write plane needs rails at all. While the server could only read, a hostile
message was just text and the worst case was a bad summary. Once delete
exists, "delete everything from the CFO" sitting in a message body would be
an instruction with consequences.

The defence is the shape of the tools rather than a filter that tries to
recognise malicious text, because filters lose. Every mutating tool takes a
list of integer UIDs and nothing else — no query, no rule, no pattern, no
"all". There is no argument through which a message could describe which
mail to act on, so a sentence asking for a deletion has nothing to attach
to. Only you, choosing messages, can start a mutation.

**Nothing is done to more mail than you looked at.** Every bulk operation
previews by default and shows exactly which messages would move and where.
Over twenty-five messages it refuses outright rather than doing the first
twenty-five, because a caller who asked for three hundred, got twenty-five,
and saw success would have no way to know.

**Every move is recorded.** Each one writes an undo manifest naming every
message, its Message-ID, the folder it left, and the UID it landed on, both
in the response and on disk under `.imap-mcp/undo/`. A response scrolls out
of a conversation; the mail stays moved. The manifest still gets written
when a batch fails halfway, which is the case that matters most.

**A move that isn't safe is refused, not approximated.** On a server without
the IMAP `MOVE` extension the classic fallback is copy, flag `\Deleted`,
expunge. That is the exact sequence the first rail exists to prevent, so the
server says so and does nothing instead.

## Safety

**Reading never modifies your mailbox.** Read sessions open with `EXAMINE`
(read-only) and every fetch uses `BODY.PEEK[]`. A plain `FETCH BODY[]` sets
the `\Seen` flag as a side effect, so a "read-only" sync would quietly mark
your unread mail as read. That holds whether or not you enable writes: the
read path and the write path are separate modules, `imap_client.py` contains
no mutating command at all, and a test fails if it ever gains one.

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

`imap_client.py` reads and never mutates; `write.py` mutates and never reads
a message body. Keeping them apart is what makes the guarantees checkable
instead of asserted: the read module can be tested for the absence of every
mutating verb, and the write module for the absence of any body fetch.

- **Second brain** — `imap_sync_to_vault` writes
  `External Inputs/<Provider>/<mailbox>/YYYY-MM-DD-<slug>.md`
- **Mycelium runtime** — `imap_export_for_runtime` emits records matching the
  runtime's `RawItem` field-for-field, so the server-side adapter wraps this
  rather than reimplementing it

## Tests

```bash
uv run pytest -q
```

130 tests, no network required.

Every security guard has been mutation-tested: the guard removed, the
matching test confirmed failing, the guard restored. For the write plane
that check is automated and reproducible rather than something someone
remembers doing —

```bash
uv run python tools/mutation_check.py
```

takes a disposable copy of the repo and, for each of twenty-four
mutations, confirms the target test passes first, breaks exactly one guard,
and confirms the same test now fails. It has already earned that twice: the
batch cap turned out to be enforced at two layers, each masking the other,
so neither was actually pinned by a test until the harness said so — and
when one of its own anchors was written wrong, it reported the mutation as
unapplied rather than scoring it caught.

**Not yet verified:** no live smoke test has run against a real mailbox on
any provider, for reading or for writing. Every test uses synthetic
fixtures, which proves the command construction and the rails but not that a
live server accepts these exact commands. Nothing here has moved a real
message.
