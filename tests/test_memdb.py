from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import memdb


TELEGRAM_CHAT_ID = "-1003743984662"
PRIMARY_THREAD_ID = "462"
SECONDARY_THREAD_ID = "463"
PRIMARY_LABEL = f"Bill Threaded id:{TELEGRAM_CHAT_ID} topic:{PRIMARY_THREAD_ID}"
SECONDARY_LABEL = f"Bill Threaded id:{TELEGRAM_CHAT_ID} topic:{SECONDARY_THREAD_ID}"


class MemdbTestCase(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "memdb.sqlite3"
        with closing(memdb.connect(str(self.db_path))) as con:
            memdb.init_db(con)

    def session_record(
        self,
        *,
        timestamp: str = "2026-03-15T12:00:00Z",
        session_id: str = "sess-1",
        cwd: str = "/tmp/workspace",
    ) -> dict[str, Any]:
        return {
            "type": "session",
            "timestamp": timestamp,
            "id": session_id,
            "cwd": cwd,
        }

    def message_record(
        self,
        *,
        timestamp: str,
        message_id: str,
        role: str,
        content: Any,
        conversation_label: str | None = None,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "type": "message",
            "timestamp": timestamp,
            "id": message_id,
            "message": {
                "role": role,
                "content": content,
            },
        }
        if conversation_label:
            record["conversation_label"] = conversation_label
        if parent_id:
            record["parentId"] = parent_id
        return record

    def write_jsonl(self, name: str, records: list[dict[str, Any]]) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n"
        path.write_text(payload, encoding="utf-8")
        return path

    def rewrite_jsonl(self, path: Path, records: list[dict[str, Any]]) -> None:
        payload = "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n"
        path.write_text(payload, encoding="utf-8")
        stat = path.stat()
        bumped_mtime = stat.st_mtime + 1.0
        os.utime(path, (bumped_mtime, bumped_mtime))

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = memdb.main(["--db", str(self.db_path), *argv])
        return code, stdout.getvalue(), stderr.getvalue()

    def run_cli_json(self, *argv: str) -> dict[str, Any]:
        code, stdout, stderr = self.run_cli(*argv)
        self.assertEqual(0, code, msg=stderr or stdout)
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"Command did not emit JSON.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}") from exc

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with closing(memdb.connect(str(self.db_path))) as con:
            memdb.init_db(con)
            return [dict(row) for row in con.execute(sql, params).fetchall()]

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
        rows = self.fetchall(sql, params)
        self.assertTrue(rows, msg=f"No rows returned for SQL: {sql!r} {params!r}")
        return rows[0]

    def scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        row = self.fetchone(sql, params)
        return next(iter(row.values()))


class MemdbTranscriptToRecallTests(MemdbTestCase):
    """Why memdb exists at runtime: durable, scoped recall from ephemeral transcripts."""

    def test_ingest_turns_fragile_session_jsonl_into_durable_linkable_memory_rows(self) -> None:
        """Ingest turns fragile transcripts into durable, linkable memory rows.

        This is the foundation of `memdb`: raw session JSONL is too temporary and too irregular
        to serve recall directly. The test proves that ingest normalizes messages and events,
        preserves tool-call lineage, and infers chat/thread scope from transcript metadata.
        """

        transcript = self.write_jsonl(
            "ingest/thread-462.jsonl",
            [
                self.session_record(),
                self.message_record(
                    timestamp="2026-03-15T12:00:01Z",
                    message_id="msg-user",
                    role="user",
                    content="Decision: Ship memdb as the durable memory backend.",
                    conversation_label=PRIMARY_LABEL,
                ),
                self.message_record(
                    timestamp="2026-03-15T12:00:02Z",
                    message_id="msg-assistant",
                    parent_id="msg-user",
                    role="assistant",
                    conversation_label=PRIMARY_LABEL,
                    content=[
                        {"type": "text", "text": "I'll check the recent scoped context."},
                        {"type": "toolCall", "name": "memory_recent", "arguments": {"n": 5}},
                    ],
                ),
                self.message_record(
                    timestamp="2026-03-15T12:00:03Z",
                    message_id="msg-tool",
                    parent_id="msg-assistant",
                    role="toolResult",
                    content="Found 5 recent messages.",
                    conversation_label=PRIMARY_LABEL,
                ),
            ],
        )

        summary = self.run_cli_json("ingest", str(transcript))
        self.assertEqual({"files": 1, "messages_added": 3, "events_added": 3}, summary)

        messages = self.fetchall(
            """
            SELECT source_line, author_role, chat_app, chat_id, thread_id, message_uid, reply_to_uid, text
            FROM messages
            ORDER BY source_line
            """
        )
        self.assertEqual(["user", "assistant", "toolResult"], [row["author_role"] for row in messages])
        self.assertEqual(["telegram", "telegram", "telegram"], [row["chat_app"] for row in messages])
        self.assertEqual([TELEGRAM_CHAT_ID, TELEGRAM_CHAT_ID, TELEGRAM_CHAT_ID], [row["chat_id"] for row in messages])
        self.assertEqual([PRIMARY_THREAD_ID, PRIMARY_THREAD_ID, PRIMARY_THREAD_ID], [row["thread_id"] for row in messages])

        assistant_message_id = self.scalar("SELECT id FROM messages WHERE message_uid = ?", ("msg-assistant",))
        tool_call = self.fetchone(
            "SELECT kind, name, origin_message_id FROM events WHERE kind = 'tool_call' LIMIT 1"
        )
        self.assertEqual("memory_recent", tool_call["name"])
        self.assertEqual(assistant_message_id, tool_call["origin_message_id"])

        tool_result_message_id = self.scalar("SELECT id FROM messages WHERE message_uid = ?", ("msg-tool",))
        tool_result = self.fetchone(
            "SELECT kind, origin_message_id, text FROM events WHERE kind = 'tool_result' LIMIT 1"
        )
        self.assertEqual("tool_result", tool_result["kind"])
        self.assertEqual(tool_result_message_id, tool_result["origin_message_id"])
        self.assertEqual("Found 5 recent messages.", tool_result["text"])

    def test_reingest_is_safe_because_unchanged_sources_are_skipped_and_changed_sources_are_replaced(self) -> None:
        """Re-ingest is safe because unchanged sources are skipped and changed sources are replaced.

        `memdb` has to support repeated backfills and maintenance runs. This test proves two key
        properties: no duplicate rows when the source did not change, and no accumulation when
        the source did change because the old rows are replaced before the new version is inserted.
        """

        transcript = self.write_jsonl(
            "ingest/reingest.jsonl",
            [
                self.session_record(),
                self.message_record(
                    timestamp="2026-03-15T12:00:01Z",
                    message_id="msg-1",
                    role="user",
                    content="Preference: Keep memory local-first and auditable.",
                    conversation_label=PRIMARY_LABEL,
                ),
            ],
        )

        first = self.run_cli_json("ingest", str(transcript))
        self.assertEqual({"files": 1, "messages_added": 1, "events_added": 1}, first)

        second = self.run_cli_json("ingest", str(transcript))
        self.assertEqual({"files": 1, "messages_added": 0, "events_added": 0}, second)

        self.rewrite_jsonl(
            transcript,
            [
                self.session_record(),
                self.message_record(
                    timestamp="2026-03-15T12:00:01Z",
                    message_id="msg-1",
                    role="user",
                    content="Preference: Keep memory local-first and auditable.",
                    conversation_label=PRIMARY_LABEL,
                ),
                self.message_record(
                    timestamp="2026-03-15T12:00:02Z",
                    message_id="msg-2",
                    role="assistant",
                    content="Lesson: SQLite makes recall deterministic and inspectable.",
                    conversation_label=PRIMARY_LABEL,
                ),
            ],
        )

        third = self.run_cli_json("ingest", str(transcript))
        self.assertEqual({"files": 1, "messages_added": 1, "events_added": 0}, third)
        self.assertEqual(
            2,
            self.scalar("SELECT COUNT(*) AS count FROM messages WHERE source_file = ?", (str(transcript),)),
        )
        self.assertEqual(
            [
                "Preference: Keep memory local-first and auditable.",
                "Lesson: SQLite makes recall deterministic and inspectable.",
            ],
            [
                row["text"]
                for row in self.fetchall(
                    "SELECT text FROM messages WHERE source_file = ? ORDER BY source_line",
                    (str(transcript),),
                )
            ],
        )

    def test_recent_and_query_stay_thread_scoped_so_memdb_prevents_cross_thread_memory_bleed(self) -> None:
        """Recent and query stay thread-scoped so memdb prevents cross-thread memory bleed.

        This is the main runtime reason `memdb` exists instead of a flat global log. The active
        reply needs the current conversation, not every similar sentence in the workspace. The test
        proves both recency recall and search stay inside the chosen chat/thread boundary.
        """

        primary_transcript = self.write_jsonl(
            "ingest/thread-462.jsonl",
            [
                self.session_record(session_id="sess-primary"),
                self.message_record(
                    timestamp="2026-03-15T12:00:01Z",
                    message_id="primary-user",
                    role="user",
                    content="The migration plan is to keep durable memory in SQLite.",
                    conversation_label=PRIMARY_LABEL,
                ),
                self.message_record(
                    timestamp="2026-03-15T12:00:02Z",
                    message_id="primary-assistant",
                    parent_id="primary-user",
                    role="assistant",
                    conversation_label=PRIMARY_LABEL,
                    content=[
                        {"type": "text", "text": "I'll pull the current scoped history."},
                        {"type": "toolCall", "name": "memory_query", "arguments": {"query": "migration plan"}},
                    ],
                ),
            ],
        )
        secondary_transcript = self.write_jsonl(
            "ingest/thread-463.jsonl",
            [
                self.session_record(session_id="sess-secondary"),
                self.message_record(
                    timestamp="2026-03-15T12:05:01Z",
                    message_id="secondary-user",
                    role="user",
                    content="The migration plan is to export memory into flat files instead.",
                    conversation_label=SECONDARY_LABEL,
                ),
            ],
        )

        self.run_cli_json("ingest", str(primary_transcript), str(secondary_transcript))

        recent = self.run_cli_json(
            "recent",
            "--chat-app",
            "telegram",
            "--chat-id",
            TELEGRAM_CHAT_ID,
            "--thread-id",
            PRIMARY_THREAD_ID,
            "--include-events",
            "-n",
            "10",
        )
        self.assertEqual(
            "telegram:-1003743984662:topic:462",
            recent["scope"]["conversation_key"],
        )
        recent_texts = [item["text"] for item in recent["results"] if item["type"] == "message"]
        self.assertIn("The migration plan is to keep durable memory in SQLite.", recent_texts)
        self.assertNotIn("The migration plan is to export memory into flat files instead.", recent_texts)
        self.assertTrue(
            any(item["type"] == "event" and item["kind"] == "tool_call" for item in recent["results"])
        )

        query = self.run_cli_json(
            "query",
            "what is the migration plan?",
            "--chat-app",
            "telegram",
            "--chat-id",
            TELEGRAM_CHAT_ID,
            "--thread-id",
            PRIMARY_THREAD_ID,
        )
        self.assertTrue(
            any(
                result["text"] == "The migration plan is to keep durable memory in SQLite."
                for result in query["results"]
            )
        )
        self.assertTrue(all(result["thread_id"] == PRIMARY_THREAD_ID for result in query["results"]))
        self.assertTrue(all("flat files" not in result["text"] for result in query["results"]))

    def test_backfill_repairs_missing_chat_scope_from_any_surviving_routing_clue_in_the_session(self) -> None:
        """Backfill repairs missing chat scope from any surviving routing clue in the session.

        Real transcripts are not always perfectly annotated. This test proves `backfill-chat`
        can recover chat/thread scope from one message that still contains routing metadata and
        propagate that scope to adjacent rows in the same session.
        """

        transcript = self.write_jsonl(
            "ingest/backfill.jsonl",
            [
                self.session_record(session_id="sess-backfill"),
                self.message_record(
                    timestamp="2026-03-15T12:00:01Z",
                    message_id="scoped-message",
                    role="user",
                    content="We should keep thread recall exact.",
                    conversation_label=PRIMARY_LABEL,
                ),
                self.message_record(
                    timestamp="2026-03-15T12:00:02Z",
                    message_id="missing-scope",
                    role="assistant",
                    content="Agreed. I will write the tests next.",
                ),
            ],
        )
        self.run_cli_json("ingest", str(transcript))

        before = self.fetchall(
            "SELECT message_uid, chat_app, chat_id, thread_id FROM messages ORDER BY source_line"
        )
        self.assertEqual("telegram", before[0]["chat_app"])
        self.assertIsNone(before[1]["chat_app"])
        self.assertIsNone(before[1]["chat_id"])
        self.assertIsNone(before[1]["thread_id"])

        summary = self.run_cli_json("backfill-chat")
        self.assertEqual(1, summary["rows_updated_propagated"])

        after = self.fetchall(
            "SELECT message_uid, chat_app, chat_id, thread_id FROM messages ORDER BY source_line"
        )
        self.assertEqual(
            [
                ("scoped-message", "telegram", TELEGRAM_CHAT_ID, PRIMARY_THREAD_ID),
                ("missing-scope", "telegram", TELEGRAM_CHAT_ID, PRIMARY_THREAD_ID),
            ],
            [
                (row["message_uid"], row["chat_app"], row["chat_id"], row["thread_id"])
                for row in after
            ],
        )


class MemdbDurableKnowledgeProjectionTests(MemdbTestCase):
    """How memdb turns durable events and conservative message markers into canonical knowledge."""

    def test_learn_records_stable_conclusions_as_explicit_durable_events_that_project_into_the_vault(self) -> None:
        """Learn records stable conclusions as durable events that project into the vault.

        Search can rediscover context, but explicit `learned` events are how `memdb` preserves
        facts that must survive across sessions. The test proves a learned decision becomes a
        typed vault note with scope, sources, summary, and evidence intact.
        """

        learned = self.run_cli_json(
            "learn",
            "--type",
            "decision",
            "--title",
            "Memdb owns durable memory",
            "--summary",
            "SQLite is the append-only source of truth, and the vault is a rebuildable view.",
            "--key",
            "durable-memory-contract",
            "--tag",
            "architecture",
            "--source-ref",
            "docs/memory-system-design.md",
            "--evidence",
            "Scoped recall reduced cross-thread noise during validation.",
            "--session-key",
            "agent:main:telegram:group:-1003743984662:topic:462",
            "--timestamp",
            "2026-03-15T12:00:00Z",
        )
        self.assertEqual("decision", learned["memory_type"])
        self.assertEqual("durable-memory-contract", learned["key"])

        vault_dir = self.root / "vault"
        build = self.run_cli_json("vault-build", "--out", str(vault_dir), "--all")
        self.assertEqual(1, build["typed_notes"])

        note_path = vault_dir / "decisions" / "durable-memory-contract.md"
        self.assertTrue(note_path.exists())
        note = note_path.read_text(encoding="utf-8")
        self.assertIn('title: "Memdb owns durable memory"', note)
        self.assertIn("memoryType: decision", note)
        self.assertIn('tags: ["architecture", "decision", "learned"]', note)
        self.assertIn('sources: ["docs/memory-system-design.md", "memdb", "memdb:event:1"]', note)
        self.assertIn("SQLite is the append-only source of truth, and the vault is a rebuildable view.", note)
        self.assertIn("conversation=telegram:-1003743984662:topic:462", note)
        self.assertIn("Scoped recall reduced cross-thread noise during validation.", note)

        index = (vault_dir / "index.md").read_text(encoding="utf-8")
        self.assertIn("| [decisions/durable-memory-contract.md](decisions/durable-memory-contract.md) | decision | yellow |", index)

    def test_vault_build_turns_conservative_inline_markers_into_rebuildable_typed_notes(self) -> None:
        """Vault-build turns conservative inline markers into rebuildable typed notes.

        `memdb` is not only an event log. It also projects a canonical markdown memory surface
        from raw conversation evidence. The test proves that explicit markers such as
        `Preference:` and `Lesson:` are extracted conservatively and rendered deterministically.
        """

        transcript = self.write_jsonl(
            "ingest/typed-items.jsonl",
            [
                self.session_record(),
                self.message_record(
                    timestamp="2026-03-15T12:00:01Z",
                    message_id="preference-1",
                    role="user",
                    content="Preference: Keep memory local-first and auditable.",
                    conversation_label=PRIMARY_LABEL,
                ),
                self.message_record(
                    timestamp="2026-03-15T12:00:02Z",
                    message_id="lesson-1",
                    role="assistant",
                    content="Lesson: Thread-scoped recall is safer than a global memory dump.",
                    conversation_label=PRIMARY_LABEL,
                ),
            ],
        )
        self.run_cli_json("ingest", str(transcript))

        vault_dir = self.root / "vault"
        build = self.run_cli_json("vault-build", "--out", str(vault_dir), "--all")
        self.assertEqual(2, build["typed_notes"])

        preference_slug = memdb._slugify("Preference: Keep memory local-first and auditable."[:60])
        lesson_slug = memdb._slugify("Lesson: Thread-scoped recall is safer than a global memory dump."[:60])

        preference_note = (vault_dir / "preferences" / f"{preference_slug}.md").read_text(encoding="utf-8")
        self.assertIn("# Preference: preference keep memory local first and auditable", preference_note)
        self.assertIn("(Generated from memdb; do not edit)", preference_note)
        self.assertIn(
            "- 2026-03-15 (telegram:-1003743984662:topic:462): Preference: Keep memory local-first and auditable.",
            preference_note,
        )

        lesson_note = (vault_dir / "lessons" / f"{lesson_slug}.md").read_text(encoding="utf-8")
        self.assertIn("memoryType: lesson", lesson_note)
        self.assertIn(
            "- 2026-03-15 (telegram:-1003743984662:topic:462): Lesson: Thread-scoped recall is safer than a global memory dump.",
            lesson_note,
        )


class MemdbInboxHygieneTests(MemdbTestCase):
    """How memdb keeps uncertain memory outside the canonical vault and strips operational noise."""

    def test_inbox_clean_preserves_reviewable_uncertainty_while_removing_prompt_and_tool_noise(self) -> None:
        """Inbox-clean preserves reviewable uncertainty while removing prompt and tool noise.

        The inbox exists because not every candidate memory is strong enough to become canonical.
        This test proves `memdb` keeps low-confidence claims outside the vault, normalizes valid
        entries, deduplicates repeats, and discards prompt/tool artifacts that should never be
        mistaken for memory.
        """

        inbox_path = self.root / "memory-inbox.md"
        inbox_path.write_text(
            "\n".join(
                [
                    "# Memory Inbox",
                    "",
                    "## 2026-03-15",
                    "- key=durable-memory category=decisions claim=memdb is the append-only source of truth for durable memory (query=durable memory source)",
                    "  - evidence: memdb:17 @ 2026-03-15T12:00:00+00:00",
                    "  - evidence: memdb:17 @ 2026-03-15T12:00:00+00:00",
                    "- Possible daemon loop mechanism alternatives discussed: cron, heartbeat batching, topic-specific event loops. Evidence: memdb:941 @ 2026-02-20T15:47:13+00:00",
                    "  - confidence: medium",
                    "- [preferences] Keep the memory system local-first and auditable.",
                    "  - evidence: memdb:27 @ 2026-03-15T12:05:00+00:00",
                    "- [preferences] Keep the memory system local-first and auditable.",
                    "  - evidence: memdb:27 @ 2026-03-15T12:05:00+00:00",
                    "- write this naturally for the user",
                    "  - evidence: toolResult output from agent",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        summary = self.run_cli_json("inbox-clean", "--path", str(inbox_path), "--write")
        self.assertEqual(5, summary["total_blocks"])
        self.assertEqual(3, summary["kept_blocks"])
        self.assertEqual(1, summary["dropped_blocks"])
        self.assertEqual(1, summary["deduped_blocks"])
        self.assertEqual(["2026-03-15"], summary["sections"])

        cleaned = inbox_path.read_text(encoding="utf-8")
        self.assertIn("This file lives outside memory/vault on purpose so builtin vault search does not treat it as canonical memory.", cleaned)
        self.assertIn("- [decisions] memdb is the append-only source of truth for durable memory.", cleaned)
        self.assertIn("  - key: durable-memory", cleaned)
        self.assertIn("  - query: durable memory source", cleaned)
        self.assertIn("- Possible daemon loop mechanism alternatives discussed: cron, heartbeat batching, topic-specific event loops.", cleaned)
        self.assertIn("- [preferences] Keep the memory system local-first and auditable.", cleaned)
        self.assertNotIn("toolResult", cleaned)
        self.assertEqual(1, cleaned.count("- [preferences] Keep the memory system local-first and auditable."))


if __name__ == "__main__":
    unittest.main()
