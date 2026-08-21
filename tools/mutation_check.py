"""Mutation harness for the write plane's safety rails.

A passing test proves nothing about a guard until you have watched the test
FAIL with the guard removed. Otherwise a test that never exercised the guard
at all — or that would pass with the guard deleted — reads exactly like a
test that is protecting something.

For each rail this: takes a disposable copy of the repo, confirms the target
test passes there UNMUTATED (the baseline; without it a broken copy or a
typo'd path reads as "the guard caught it"), removes or weakens exactly one
guard, confirms the same test now FAILS, and restores.

Run it with:  uv run python tools/mutation_check.py

Not under tests/, so pytest does not collect it — this is slow and copies
the tree. It exists so the mutation claim in the README is reproducible
rather than something someone remembers doing once.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# A single backslash, named so escaping-heavy anchors stay legible below.
_BS = chr(92)


@dataclass
class Mutation:
    rail: str
    name: str
    target_file: str
    edits: list[tuple[str, str]]
    test: str
    extra_edits: dict[str, list[tuple[str, str]]] = field(default_factory=dict)


MUTATIONS = [
    Mutation(
        rail="1 never expunge",
        name="allow the EXPUNGE verb through the chokepoint",
        target_file="imap_mcp/write.py",
        edits=[
            ("    if _EXPUNGE_RE.search(normalised):", "    if False:"),
            (
                '_ALLOWED_MUTATIONS = frozenset({"UID MOVE", "UID COPY", "UID STORE", "APPEND"})',
                '_ALLOWED_MUTATIONS = frozenset({"UID MOVE", "UID COPY", "UID STORE", "APPEND", "EXPUNGE", "UID EXPUNGE"})',
            ),
        ],
        test="tests/test_write_never_expunges.py::test_expunge_verb_is_refused",
    ),
    Mutation(
        rail="1 never expunge",
        name="allow the \\Deleted flag to be set",
        target_file="imap_mcp/write.py",
        edits=[
            ("        if _DELETED_FLAG_RE.search(flag):", "        if False:"),
            (
                '_ALLOWED_FLAGS = frozenset({"\\\\Seen", "\\\\Flagged", "\\\\Answered", "\\\\Draft"})',
                '_ALLOWED_FLAGS = frozenset({"\\\\Seen", "\\\\Flagged", "\\\\Answered", "\\\\Draft", "\\\\Deleted"})',
            ),
        ],
        test="tests/test_write_never_expunges.py::test_deleted_flag_is_refused",
    ),
    Mutation(
        rail="1 never expunge",
        name="silently downgrade to the COPY+EXPUNGE move on a server without MOVE",
        target_file="imap_mcp/write.py",
        edits=[('    if "MOVE" not in caps:', "    if False:")],
        test="tests/test_write_never_expunges.py::test_a_server_without_MOVE_is_refused_not_downgraded",
    ),
    Mutation(
        rail="1 never expunge",
        name="close the mailbox at teardown (an implicit EXPUNGE)",
        target_file="imap_mcp/imap_client.py",
        edits=[
            (
                "        try:\n            conn.logout()\n        except Exception:\n            pass\n",
                "        try:\n            conn.close()\n        except Exception:\n            pass\n        try:\n            conn.logout()\n        except Exception:\n            pass\n",
            )
        ],
        test="tests/test_write_never_expunges.py::test_teardown_never_closes_a_mailbox",
    ),
    Mutation(
        rail="1 never expunge",
        name="let an approved verb carry a \\Deleted flag argument",
        target_file="imap_mcp/write.py",
        edits=[
            (
                "        if isinstance(argument, str) and _DELETED_FLAG_IN_ARG_RE.search(argument):",
                "        if False:",
            )
        ],
        test="tests/test_write_never_expunges.py::test_the_chokepoint_refuses_deleted_even_when_called_directly",
    ),
    Mutation(
        rail="1 never expunge",
        name="re-broaden the argument scan so it matches a folder NAMED Deleted Messages",
        target_file="imap_mcp/write.py",
        edits=[
            (
                "        if isinstance(argument, str) and _DELETED_FLAG_IN_ARG_RE.search(argument):",
                "        if isinstance(argument, str) and _DELETED_FLAG_RE.search(argument):",
            )
        ],
        test="tests/test_write_never_expunges.py::test_a_mailbox_named_like_the_flag_is_still_usable",
    ),
    Mutation(
        rail="1 never expunge",
        name="stop escaping backslashes in mailbox names (quoted-string escape)",
        target_file="imap_mcp/imap_client.py",
        # Built with chr(92) rather than written as a literal. The target
        # line is itself four levels of backslash escaping, and spelling it
        # inline is how this anchor was wrong the first time — the harness
        # reported it as unapplied rather than scoring it caught, which is
        # the behaviour that made the mistake visible instead of silent.
        edits=[
            (
                '    body = "".join(out).replace("'
                + _BS * 2
                + '", "'
                + _BS * 4
                + '").replace(\'"\', \''
                + _BS * 2
                + '"\')',
                '    body = "".join(out).replace(\'"\', \''
                + _BS * 2
                + '"\')',
            )
        ],
        test="tests/test_write_never_expunges.py::test_a_mailbox_name_cannot_escape_its_quoted_string",
    ),
    Mutation(
        rail="5 capped, previewed, reversible",
        name="stop deduping repeated UIDs",
        target_file="imap_mcp/server.py",
        edits=[
            (
                "    uids = [u for u in parsed if not (u in seen or seen.add(u))]",
                "    uids = list(parsed)",
            )
        ],
        test="tests/test_write_bulk.py::test_duplicate_uids_are_collapsed",
    ),
    Mutation(
        rail="2 never send",
        name="allow send-shaped verbs through the chokepoint",
        target_file="imap_mcp/write.py",
        edits=[("    if _SEND_RE.search(normalised):", "    if False:")],
        test="tests/test_write_never_sends.py::test_send_shaped_verbs_are_refused",
    ),
    Mutation(
        rail="2 never send",
        name="put an SMTP endpoint back in the provider table",
        target_file="imap_mcp/providers.py",
        edits=[
            (
                '    imap_port: int = 993\n',
                '    imap_port: int = 993\n    smtp_host: Optional[str] = "smtp.example.com"\n',
            )
        ],
        test="tests/test_write_never_sends.py::test_provider_profiles_carry_no_smtp_endpoint",
    ),
    Mutation(
        rail="3 content cannot mutate",
        name="give the delete tool a free-text selector",
        target_file="imap_mcp/server.py",
        edits=[
            (
                "def imap_delete_messages(\n    uids: list[int],\n    mailbox: str = \"INBOX\",",
                "def imap_delete_messages(\n    uids: list[int],\n    query: str = \"\",\n    mailbox: str = \"INBOX\",",
            )
        ],
        test="tests/test_write_no_injection.py::test_no_mutating_tool_accepts_a_selector",
    ),
    Mutation(
        rail="3 content cannot mutate",
        name="let the write plane read message bodies",
        target_file="imap_mcp/write.py",
        edits=[
            (
                "from imap_mcp.imap_client import IMAPError, _classify, encode_mailbox",
                "from imap_mcp.imap_client import IMAPError, _classify, encode_mailbox\nfrom imap_mcp import normalize",
            )
        ],
        test="tests/test_write_no_injection.py::test_the_write_plane_never_reads_a_body",
    ),
    Mutation(
        rail="3 content cannot mutate",
        name="drop the required-uids guarantee (default to acting on nothing named)",
        target_file="imap_mcp/server.py",
        edits=[
            (
                "def imap_archive_messages(\n    uids: list[int],",
                "def imap_archive_messages(\n    uids: list[int] = [],",
            )
        ],
        test="tests/test_write_no_injection.py::test_every_mutating_tool_requires_explicit_uids",
    ),
    Mutation(
        rail="4 atomic read-then-act",
        name="stop checking UIDVALIDITY before mutating",
        target_file="imap_mcp/write.py",
        edits=[
            (
                "    uidvalidity = select_writable(conn, source_mailbox)\n    if expect_uidvalidity is not None and int(expect_uidvalidity) != uidvalidity:",
                "    uidvalidity = select_writable(conn, source_mailbox)\n    if False:",
            )
        ],
        test="tests/test_write_atomicity.py::test_a_renumbered_mailbox_refuses_before_mutating_anything",
    ),
    Mutation(
        rail="4 atomic read-then-act",
        name="stop re-verifying the UID immediately before its mutation",
        target_file="imap_mcp/write.py",
        edits=[
            (
                "    actual = peek_message_id(conn, uid)\n    if actual is None:",
                "    actual = peek_message_id(conn, uid) or ''\n    if False:",
            )
        ],
        test="tests/test_write_atomicity.py::test_a_vanished_message_refuses_instead_of_moving_nothing",
    ),
    Mutation(
        rail="4 atomic read-then-act",
        name="lose the records of mail that moved before a mid-batch failure",
        target_file="imap_mcp/write.py",
        edits=[("            if records:", "            if False:")],
        test="tests/test_write_atomicity.py::test_a_concurrent_delete_inside_the_check_to_act_gap",
    ),
    # The cap lives at two layers. Each mutation below targets the ONE test
    # that the other layer cannot mask — removing the tool-layer cap is only
    # observable on the preview path, and removing the inner cap is only
    # observable by calling write.move_uids directly. Pointing both at the
    # same tool-level test is how this rail looked protected while neither
    # guard was actually pinned.
    Mutation(
        rail="5 capped, previewed, reversible",
        name="remove the tool-layer cap (observable only on the preview path)",
        target_file="imap_mcp/server.py",
        edits=[
            (
                "    if len(uids) > write.MAX_BULK:\n        return [], {",
                "    if False:\n        return [], {",
            )
        ],
        test="tests/test_write_bulk.py::test_the_cap_applies_to_previews_too",
    ),
    Mutation(
        rail="5 capped, previewed, reversible",
        name="remove the inner cap in write.move_uids",
        target_file="imap_mcp/write.py",
        edits=[
            (
                "    if len(uids) > MAX_BULK:\n        raise RailViolation(\n            f\"refusing {len(uids)} messages in one operation; the cap is \"\n            f\"{MAX_BULK}. This is a refusal, not a truncation — nothing was \"\n            \"changed. Split the work into smaller batches you can check.\"\n        )",
                "    if False:\n        raise RailViolation(\"unreachable\")",
            )
        ],
        test="tests/test_write_bulk.py::test_the_inner_cap_holds_on_its_own",
    ),
    Mutation(
        rail="5 capped, previewed, reversible",
        name="make deletion act immediately instead of previewing",
        target_file="imap_mcp/server.py",
        edits=[
            (
                "    expect_uidvalidity: Optional[int] = None,\n    dry_run: bool = True,\n) -> dict[str, Any]:\n    \"\"\"Delete messages",
                "    expect_uidvalidity: Optional[int] = None,\n    dry_run: bool = False,\n) -> dict[str, Any]:\n    \"\"\"Delete messages",
            )
        ],
        test="tests/test_write_bulk.py::test_dry_run_is_the_default_on_every_destructive_tool",
    ),
    Mutation(
        rail="5 capped, previewed, reversible",
        name="stop persisting the undo manifest",
        target_file="imap_mcp/vault.py",
        edits=[
            (
                "    try:\n        path.parent.mkdir(parents=True, exist_ok=True)\n        tmp = path.with_suffix(\".json.tmp\")",
                "    if True:\n        return {\n            \"undo_manifest_path\": None,\n            \"undo_manifest_error\": None,\n            \"vault_root\": str(root),\n            \"root_source\": root_source,\n        }\n    try:\n        path.parent.mkdir(parents=True, exist_ok=True)\n        tmp = path.with_suffix(\".json.tmp\")",
            )
        ],
        test="tests/test_write_bulk.py::test_the_undo_manifest_survives_the_conversation",
    ),
    Mutation(
        rail="0 separate opt-in surface",
        name="register the write plane whether or not the operator opted in",
        target_file="imap_mcp/server.py",
        edits=[
            (
                'return (os.environ.get(ENV_ENABLE_WRITES) or "").strip().lower() in _TRUTHY',
                "return True",
            )
        ],
        test="tests/test_write_optin.py::test_no_mailbox_write_tool_exists_by_default",
    ),
    Mutation(
        rail="0 separate opt-in surface",
        name="treat any value of the flag as opting in",
        target_file="imap_mcp/server.py",
        edits=[
            (
                'return (os.environ.get(ENV_ENABLE_WRITES) or "").strip().lower() in _TRUTHY',
                "return os.environ.get(ENV_ENABLE_WRITES) is not None",
            )
        ],
        test="tests/test_write_optin.py::test_the_flag_is_read_strictly",
    ),
    Mutation(
        rail="6 honest annotations",
        name="hide the destructive hint on tools that move mail",
        target_file="imap_mcp/server.py",
        edits=[
            (
                'MOVES_MAIL = {\n    "readOnlyHint": False,\n    "destructiveHint": True,',
                'MOVES_MAIL = {\n    "readOnlyHint": False,\n    "destructiveHint": False,',
            )
        ],
        test="tests/test_server_smoke.py::test_destructive_hints_are_honest",
    ),
    Mutation(
        rail="6 honest annotations",
        name="mark a mailbox-mutating tool as read-only",
        target_file="imap_mcp/server.py",
        edits=[
            (
                'CHANGES_FLAGS = {\n    "readOnlyHint": False,',
                'CHANGES_FLAGS = {\n    "readOnlyHint": True,',
            )
        ],
        test="tests/test_server_smoke.py::test_the_read_only_set_is_exactly_pinned",
    ),
]


def run_test(workdir: Path, test: str) -> bool:
    """True when the test PASSES."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", test],
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="imap-mcp-mutation-") as tmp:
        workdir = Path(tmp) / "repo"
        shutil.copytree(
            REPO,
            workdir,
            ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__"),
        )

        failures: list[str] = []
        baselines: set[str] = set()

        for mutation in MUTATIONS:
            # BASELINE. Without this a wrong path or a broken copy would make
            # every mutation look successfully caught.
            if mutation.test not in baselines:
                if not run_test(workdir, mutation.test):
                    print(f"BASELINE FAILED (harness bug, not a finding): {mutation.test}")
                    failures.append(f"baseline: {mutation.test}")
                    continue
                baselines.add(mutation.test)

            target = workdir / mutation.target_file
            original = target.read_text()
            mutated = original
            applied = True
            for old, new in mutation.edits:
                if mutated.count(old) != 1:
                    print(
                        f"MUTATION DID NOT APPLY (harness bug): {mutation.name} "
                        f"-> anchor found {mutated.count(old)} times"
                    )
                    failures.append(f"unapplied: {mutation.name}")
                    applied = False
                    break
                mutated = mutated.replace(old, new)
            if not applied:
                continue

            target.write_text(mutated)
            try:
                still_passes = run_test(workdir, mutation.test)
            finally:
                target.write_text(original)

            if still_passes:
                print(f"NOT CAUGHT  [rail {mutation.rail}] {mutation.name}")
                print(f"            {mutation.test} passed with the guard removed")
                failures.append(mutation.name)
            else:
                print(f"caught      [rail {mutation.rail}] {mutation.name}")

        print()
        if failures:
            print(f"{len(failures)} of {len(MUTATIONS)} mutations were NOT caught:")
            for name in failures:
                print(f"  - {name}")
            return 1
        print(f"all {len(MUTATIONS)} mutations caught; every rail has a test that fails without it")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
