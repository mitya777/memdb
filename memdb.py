#!/usr/bin/env python3
"""memdb: raw-everything local memory log in SQLite (+ FTS5).

V1 goals:
- init DB (schema + FTS)
- ingest OpenClaw session transcripts (*.jsonl)
- query: last N messages, search (FTS)

Design: keep it dead-simple and auditable (no hashing yet).
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import re
import shutil
import sqlite3
import sys
from typing import Any, Iterable, Optional, Tuple


def _utc_ms_from_iso(ts: str) -> int:
    # Example: 2026-02-15T07:00:00.553Z
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        d = dt.datetime.fromisoformat(ts)
        return int(d.timestamp() * 1000)
    except Exception:
        return 0


def _ensure_parent(path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)


def connect(db_path: str) -> sqlite3.Connection:
    _ensure_parent(db_path)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA foreign_keys=ON;")
    return con


SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS ingest_state (
  source TEXT PRIMARY KEY,
  mtime_ms INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_file TEXT NOT NULL,
  source_line INTEGER NOT NULL,

  ts_ms INTEGER NOT NULL,
  session_id TEXT,
  session_key TEXT,

  chat_app TEXT,
  chat_type TEXT,
  chat_id TEXT,
  thread_id TEXT,

  author_role TEXT,
  author_id TEXT,
  author_name TEXT,

  message_uid TEXT,          -- transcript message.id (if present)
  reply_to_uid TEXT,

  text TEXT,
  raw_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts_ms);
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_app, chat_id);
CREATE INDEX IF NOT EXISTS idx_messages_chat_thread ON messages(chat_app, chat_id, thread_id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_messages_uid ON messages(source_file, message_uid);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_messages_source_line ON messages(source_file, source_line);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_file TEXT NOT NULL,
  source_line INTEGER NOT NULL,

  ts_ms INTEGER NOT NULL,
  session_id TEXT,
  session_key TEXT,

  origin_message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,

  kind TEXT NOT NULL,         -- tool_call|tool_result|system|model_change|custom|...
  name TEXT,                  -- tool name / customType / etc.
  input_json TEXT,
  output_json TEXT,
  text TEXT,
  raw_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ms);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
-- idx_events_origin_message_id is created in _migrate_db for compatibility with older DBs.

-- FTS
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
  text,
  content='messages',
  content_rowid='id',
  tokenize='porter'
);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  text,
  content='events',
  content_rowid='id',
  tokenize='porter'
);

-- Triggers keep FTS in sync
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts(rowid, text) VALUES (new.id, coalesce(new.text,''));
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text) VALUES('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text) VALUES('delete', old.id, old.text);
  INSERT INTO messages_fts(rowid, text) VALUES (new.id, coalesce(new.text,''));
END;

CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
  INSERT INTO events_fts(rowid, text) VALUES (new.id, coalesce(new.text,''));
END;
CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
  INSERT INTO events_fts(events_fts, rowid, text) VALUES('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
  INSERT INTO events_fts(events_fts, rowid, text) VALUES('delete', old.id, old.text);
  INSERT INTO events_fts(rowid, text) VALUES (new.id, coalesce(new.text,''));
END;
"""


def _column_exists(con: sqlite3.Connection, table: str, column: str) -> bool:
    rows = con.execute(f"PRAGMA table_info({table})").fetchall()
    return any(str(r[1]) == column for r in rows)


def _migrate_db(con: sqlite3.Connection) -> None:
    # Add events.origin_message_id for event→message linkage.
    if not _column_exists(con, "events", "origin_message_id"):
        con.execute("ALTER TABLE events ADD COLUMN origin_message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL")

    con.execute("CREATE INDEX IF NOT EXISTS idx_events_origin_message_id ON events(origin_message_id)")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS uniq_messages_source_line ON messages(source_file, source_line)")

    # Backfill linkage for existing rows when event and message share source_file+source_line.
    con.execute(
        """
        UPDATE events
        SET origin_message_id = (
          SELECT m.id
          FROM messages m
          WHERE m.source_file = events.source_file
            AND m.source_line = events.source_line
          LIMIT 1
        )
        WHERE origin_message_id IS NULL
        """
    )


def init_db(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA_SQL)
    _migrate_db(con)
    con.commit()


def _flatten_content(content: Any) -> str:
    """OpenAI-style message.content is often a list of {type,text} blocks."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                t = block.get("type")
                if t in ("text", "thinking"):
                    parts.append(block.get("text") or block.get("thinking") or "")
                else:
                    # best-effort stringify
                    if "text" in block:
                        parts.append(str(block.get("text")))
        return "\n".join([p for p in parts if p])
    if isinstance(content, dict):
        if "text" in content:
            return str(content.get("text"))
    return str(content)


_CONV_LABEL_RE = re.compile(r'"conversation_label"\s*:\s*"([^"]+)"')
_TREECHAT_TARGET_STREAM_RE = re.compile(
    r'"target_stream_id"\s*:\s*"([^"]+)"|^\s*-\s*target_stream_id:\s*(\S+)',
    re.MULTILINE,
)
_TREECHAT_TOPIC_ID_RE = re.compile(
    r'"topic_id"\s*:\s*"([^"]+)"|^\s*-\s*topic_id:\s*(\S+)',
    re.MULTILINE,
)
_TREECHAT_CONTEXT_RE = re.compile(r"\bTreechat invocation context\b", re.IGNORECASE)
_TREECHAT_CURRENT_MESSAGE_RE = re.compile(r"Current inbound Treechat message:\s*(.+)\Z", re.S)
_TREECHAT_TOPIC_PATH_RE = re.compile(
    r"-(?:topic|thread)-([0-9a-fA-F]{8,}(?:-[0-9a-fA-F]{4,}){1,})\.jsonl$",
    re.IGNORECASE,
)


def _first_match_group(pattern: re.Pattern[str], text: str) -> Optional[str]:
    if not text:
        return None
    match = pattern.search(text)
    if not match:
        return None
    groups = match.groups()
    if groups:
        for group in groups:
            value = (group or "").strip()
            if value:
                return value
    value = (match.group(0) or "").strip()
    return value or None


def _infer_treechat_thread_from_source_file(source_file: Optional[str]) -> Optional[str]:
    if not source_file:
        return None
    match = _TREECHAT_TOPIC_PATH_RE.search(source_file)
    if not match:
        return None
    value = (match.group(1) or "").strip()
    return value or None


def _infer_treechat_fields(
    text: str,
    *,
    source_file: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if not text:
        return (None, None, None)

    stream_id = _first_match_group(_TREECHAT_TARGET_STREAM_RE, text)
    thread_id = _first_match_group(_TREECHAT_TOPIC_ID_RE, text) or _infer_treechat_thread_from_source_file(
        source_file
    )
    has_treechat_context = bool(stream_id or thread_id or _TREECHAT_CONTEXT_RE.search(text))
    if not has_treechat_context:
        return (None, None, None)
    return ("treechat", stream_id, thread_id)


def _infer_chat_fields_from_raw_obj(
    obj: dict,
    *,
    source_file: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Best-effort inference for chat_app/chat_id/thread_id from a raw JSONL envelope.

    We don't want to overfit to one log shape, so we:
    - look for conversation_label patterns in a compact JSON serialization
    - reuse the same parser as text-based inference
    """
    try:
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    return _infer_chat_fields_from_text(s, source_file=source_file)


def _infer_chat_fields_from_text(
    text: str,
    *,
    source_file: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Best-effort inference for chat_app/chat_id/thread_id from a string.

    Source string can be:
    - message text (sometimes contains embedded JSON)
    - serialized raw JSON (raw_json)

    This is intentionally conservative and only uses patterns we already see
    (conversation_label → a human-readable label that encodes routing).

    Examples seen:
      - "telegram:332145937"
      - "Bill Threaded id:-1003743984662 topic:462"
      - "Dmitriy Fabrikant (@metamitya) id:332145937"
    """
    if not text:
        return (None, None, None)

    treechat_app, treechat_chat_id, treechat_thread_id = _infer_treechat_fields(
        text,
        source_file=source_file,
    )
    if treechat_app:
        return (treechat_app, treechat_chat_id, treechat_thread_id)

    m = _CONV_LABEL_RE.search(text)
    if not m:
        return (None, None, None)

    label = (m.group(1) or "").strip()
    if not label:
        return (None, None, None)

    chat_app: Optional[str] = None
    chat_id: Optional[str] = None
    thread_id: Optional[str] = None

    # Direct prefix: telegram:<id>
    if label.startswith("telegram:"):
        chat_app = "telegram"
        chat_id = label.split(":", 1)[1].strip() or None
    else:
        # Generic patterns: id:<num> and topic:<num>
        idm = re.search(r"\bid:([-0-9]+)\b", label)
        if idm:
            chat_id = idm.group(1)
        topm = re.search(r"\btopic:([0-9]+)\b", label)
        if topm:
            thread_id = topm.group(1)

        # If it looks like a Telegram label, assume telegram.
        if (
            "topic:" in label
            or (chat_id and str(chat_id).startswith("-") and "Threaded" in label)
            or ("(@" in label and " id:" in label)
        ):
            chat_app = "telegram"

    return (chat_app, chat_id, thread_id)


def _normalize_recall_text(text: Optional[str]) -> str:
    raw = (text or "").strip()
    if not raw:
        return ""

    match = _TREECHAT_CURRENT_MESSAGE_RE.search(raw)
    if match:
        extracted = (match.group(1) or "").strip()
        if extracted:
            raw = extracted

    lines = [line.rstrip() for line in raw.replace("\r", "").splitlines()]
    compact = "\n".join([line for line in lines if line.strip()]).strip()
    if len(compact) <= 800:
        return compact
    return compact[:797].rstrip() + "..."


def _insert_message(
    con: sqlite3.Connection,
    *,
    source_file: str,
    source_line: int,
    ts_ms: int,
    session_id: Optional[str],
    session_key: Optional[str],
    chat_app: Optional[str],
    chat_type: Optional[str],
    chat_id: Optional[str],
    thread_id: Optional[str],
    author_role: Optional[str],
    author_id: Optional[str],
    author_name: Optional[str],
    message_uid: Optional[str],
    reply_to_uid: Optional[str],
    text: str,
    raw_obj: dict,
) -> Optional[int]:
    cur = con.execute(
        """
        INSERT OR IGNORE INTO messages(
          source_file, source_line, ts_ms, session_id, session_key,
          chat_app, chat_type, chat_id, thread_id,
          author_role, author_id, author_name,
          message_uid, reply_to_uid,
          text, raw_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            source_file,
            source_line,
            ts_ms,
            session_id,
            session_key,
            chat_app,
            chat_type,
            chat_id,
            thread_id,
            author_role,
            author_id,
            author_name,
            message_uid,
            reply_to_uid,
            text,
            json.dumps(raw_obj, ensure_ascii=False),
        ),
    )
    if cur.lastrowid:
        return int(cur.lastrowid)

    row = con.execute(
        "SELECT id FROM messages WHERE source_file=? AND source_line=? LIMIT 1",
        (source_file, source_line),
    ).fetchone()
    return int(row["id"]) if row else None


def _insert_event(
    con: sqlite3.Connection,
    *,
    source_file: str,
    source_line: int,
    ts_ms: int,
    session_id: Optional[str],
    session_key: Optional[str],
    origin_message_id: Optional[int],
    kind: str,
    name: Optional[str],
    input_json: Optional[dict],
    output_json: Optional[dict],
    text: Optional[str],
    raw_obj: dict,
) -> Optional[int]:
    cur = con.execute(
        """
        INSERT INTO events(
          source_file, source_line, ts_ms, session_id, session_key,
          origin_message_id,
          kind, name, input_json, output_json, text, raw_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            source_file,
            source_line,
            ts_ms,
            session_id,
            session_key,
            origin_message_id,
            kind,
            name,
            json.dumps(input_json, ensure_ascii=False) if input_json is not None else None,
            json.dumps(output_json, ensure_ascii=False) if output_json is not None else None,
            text,
            json.dumps(raw_obj, ensure_ascii=False),
        ),
    )
    return int(cur.lastrowid) if cur.lastrowid else None


def ingest_jsonl(con: sqlite3.Connection, path: str, *, force: bool = False, chat_app: Optional[str] = None) -> Tuple[int, int]:
    """Returns (messages_added, events_added)."""

    st = os.stat(path)
    mtime_ms = int(st.st_mtime * 1000)
    size = int(st.st_size)

    row = con.execute("SELECT source, mtime_ms, bytes FROM ingest_state WHERE source=?", (path,)).fetchone()
    if not force and row and int(row["mtime_ms"]) == mtime_ms and int(row["bytes"]) == size:
        return (0, 0)

    session_id = None
    session_key = None

    messages_before = con.execute("SELECT count(1) c FROM messages WHERE source_file=?", (path,)).fetchone()["c"]
    events_before = con.execute("SELECT count(1) c FROM events WHERE source_file=?", (path,)).fetchone()["c"]

    # If re-ingesting changed file: simplest is delete prior rows for that source, then reinsert.
    if row:
        con.execute("DELETE FROM messages WHERE source_file=?", (path,))
        con.execute("DELETE FROM events WHERE source_file=?", (path,))

    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip("\n")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                _insert_event(
                    con,
                    source_file=path,
                    source_line=idx,
                    ts_ms=0,
                    session_id=session_id,
                    session_key=session_key,
                    origin_message_id=None,
                    kind="parse_error",
                    name=None,
                    input_json=None,
                    output_json=None,
                    text=line[:5000],
                    raw_obj={"raw": line},
                )
                continue

            typ = obj.get("type")
            ts_ms = _utc_ms_from_iso(obj.get("timestamp") or "")

            if typ == "session":
                session_id = obj.get("id") or session_id
                # session-level event
                _insert_event(
                    con,
                    source_file=path,
                    source_line=idx,
                    ts_ms=ts_ms,
                    session_id=session_id,
                    session_key=session_key,
                    origin_message_id=None,
                    kind="session",
                    name=None,
                    input_json=None,
                    output_json=None,
                    text=f"session start cwd={obj.get('cwd')}",
                    raw_obj=obj,
                )
                continue

            if typ in ("model_change", "thinking_level_change", "custom"):
                name = obj.get("modelId") or obj.get("customType") or obj.get("thinkingLevel")
                _insert_event(
                    con,
                    source_file=path,
                    source_line=idx,
                    ts_ms=ts_ms,
                    session_id=session_id,
                    session_key=session_key,
                    origin_message_id=None,
                    kind=typ,
                    name=name,
                    input_json=obj,
                    output_json=None,
                    text=None,
                    raw_obj=obj,
                )
                continue

            if typ == "message":
                m = obj.get("message") or {}
                role = (m.get("role") or "").strip() or None
                content = m.get("content")
                text = _flatten_content(content)

                # Best-effort inference from both raw envelope + text.
                raw_app, raw_chat_id, raw_thread_id = _infer_chat_fields_from_raw_obj(
                    obj,
                    source_file=path,
                )
                txt_app, txt_chat_id, txt_thread_id = (None, None, None)
                if text:
                    txt_app, txt_chat_id, txt_thread_id = _infer_chat_fields_from_text(
                        text,
                        source_file=path,
                    )

                inferred_app = raw_app or txt_app
                inferred_chat_id = raw_chat_id or txt_chat_id
                inferred_thread_id = raw_thread_id or txt_thread_id

                # If caller provides chat_app explicitly, prefer it; otherwise use inferred.
                use_app = chat_app or inferred_app

                origin_message_id = _insert_message(
                    con,
                    source_file=path,
                    source_line=idx,
                    ts_ms=ts_ms,
                    session_id=session_id,
                    session_key=session_key,
                    chat_app=use_app,
                    chat_type=None,
                    chat_id=inferred_chat_id,
                    thread_id=inferred_thread_id,
                    author_role=role,
                    author_id=None,
                    author_name=None,
                    message_uid=obj.get("id"),
                    reply_to_uid=obj.get("parentId"),
                    text=text,
                    raw_obj=obj,
                )

                # Also ingest toolCalls embedded inside assistant message content blocks (OpenClaw format)
                if role == "assistant" and isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "toolCall":
                            _insert_event(
                                con,
                                source_file=path,
                                source_line=idx,
                                ts_ms=ts_ms,
                                session_id=session_id,
                                session_key=session_key,
                                origin_message_id=origin_message_id,
                                kind="tool_call",
                                name=block.get("name"),
                                input_json=block.get("arguments"),
                                output_json=None,
                                text=None,
                                raw_obj={"envelope": obj, "toolCall": block},
                            )

                # Link tool result messages to their originating message row too.
                if role == "toolResult":
                    _insert_event(
                        con,
                        source_file=path,
                        source_line=idx,
                        ts_ms=ts_ms,
                        session_id=session_id,
                        session_key=session_key,
                        origin_message_id=origin_message_id,
                        kind="tool_result",
                        name=None,
                        input_json=None,
                        output_json=obj,
                        text=text,
                        raw_obj=obj,
                    )
                continue

            # tool results come as messages with role=toolResult in this log format
            if typ == "message" and (obj.get("message") or {}).get("role") == "toolResult":
                pass

            # Some logs encode tool results as type=message role=toolResult; we already handle type=message above.
            if typ == "message":
                continue

            if typ == "tool_result":
                _insert_event(
                    con,
                    source_file=path,
                    source_line=idx,
                    ts_ms=ts_ms,
                    session_id=session_id,
                    session_key=session_key,
                    origin_message_id=None,
                    kind="tool_result",
                    name=obj.get("toolName"),
                    input_json=None,
                    output_json=obj,
                    text=_flatten_content(obj.get("content")),
                    raw_obj=obj,
                )
                continue

            # Fallback: store as event
            _insert_event(
                con,
                source_file=path,
                source_line=idx,
                ts_ms=ts_ms,
                session_id=session_id,
                session_key=session_key,
                origin_message_id=None,
                kind=typ or "unknown",
                name=None,
                input_json=obj,
                output_json=None,
                text=None,
                raw_obj=obj,
            )

    now_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
    con.execute(
        "INSERT OR REPLACE INTO ingest_state(source, mtime_ms, bytes, updated_at_ms) VALUES(?,?,?,?)",
        (path, mtime_ms, size, now_ms),
    )

    con.commit()

    messages_after = con.execute("SELECT count(1) c FROM messages WHERE source_file=?", (path,)).fetchone()["c"]
    events_after = con.execute("SELECT count(1) c FROM events WHERE source_file=?", (path,)).fetchone()["c"]
    return (int(messages_after - messages_before), int(events_after - events_before))


def cmd_ingest(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)

    patterns = args.paths
    files: list[str] = []
    for p in patterns:
        files.extend(glob.glob(p, recursive=True))
    files = sorted(set([f for f in files if os.path.isfile(f)]))
    if not files:
        print("No files matched.", file=sys.stderr)
        return 2

    total_m = 0
    total_e = 0
    for f in files:
        dm, de = ingest_jsonl(con, f, force=args.force, chat_app=args.chat_app)
        total_m += dm
        total_e += de

    print(json.dumps({"files": len(files), "messages_added": total_m, "events_added": total_e}, indent=2))
    return 0


def _fmt_ts(ts_ms: int) -> str:
    if not ts_ms:
        return "?"
    d = dt.datetime.fromtimestamp(ts_ms / 1000, tz=dt.timezone.utc)
    return d.isoformat(timespec="seconds")


LEARNED_MEMORY_TYPES = (
    "commitment",
    "decision",
    "handoff",
    "lesson",
    "person",
    "preference",
    "project",
)

TYPE_TO_DIR = {
    "commitment": "commitments",
    "decision": "decisions",
    "handoff": "handoffs",
    "lesson": "lessons",
    "person": "people",
    "preference": "preferences",
    "project": "projects",
}

TYPED_VAULT_DIRS = tuple(sorted(set(TYPE_TO_DIR.values())))
DEFAULT_MEMORY_INBOX_PATH = "/root/clawd/state/memory-inbox.md"
_LEGACY_VAULT_ROLLUP_RE = re.compile(r"^\d{4}\.md$", re.IGNORECASE)

TYPE_PRIORITY = {
    "commitment": "yellow",
    "decision": "yellow",
    "handoff": "yellow",
    "lesson": "red",
    "person": "green",
    "preference": "yellow",
    "project": "green",
}


def _normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        item = value.strip()
        return [item] if item else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                out.append(text)
        return out
    text = str(value).strip()
    return [text] if text else []


def _load_json_object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _default_priority_for_memory_type(memory_type: str) -> str:
    return TYPE_PRIORITY.get(memory_type, "yellow")


def _build_conversation_key(
    chat_app: Optional[str],
    chat_id: Optional[str],
    thread_id: Optional[str],
) -> Optional[str]:
    app = (chat_app or "").strip()
    cid = (chat_id or "").strip()
    tid = (thread_id or "").strip()
    if not app or not cid:
        return None
    if tid:
        return f"{app}:{cid}:topic:{tid}"
    return f"{app}:{cid}"


def _coalesce_scope_from_session_key(
    session_key: Optional[str],
    *,
    chat_app: Optional[str] = None,
    chat_id: Optional[str] = None,
    thread_id: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    raw = (session_key or "").strip()
    use_app = (chat_app or "").strip() or None
    use_chat_id = (chat_id or "").strip() or None
    use_thread_id = (thread_id or "").strip() or None
    if not raw:
        return (use_app, use_chat_id, use_thread_id)

    parts = [p.strip() for p in raw.split(":") if p.strip()]
    if len(parts) >= 3 and parts[0].lower() == "agent":
        parts = parts[2:]
    if not parts:
        return (use_app, use_chat_id, use_thread_id)

    channel = parts[0].lower()
    if not use_app:
        use_app = channel

    if channel == "treechat":
        for idx, token in enumerate(parts[:-1]):
            if token.lower() in ("thread", "topic"):
                use_thread_id = use_thread_id or parts[idx + 1]
        return (use_app, use_chat_id, use_thread_id)

    for idx, token in enumerate(parts[:-1]):
        normalized = token.lower()
        value = parts[idx + 1]
        if normalized in ("direct", "dm", "group", "channel"):
            use_chat_id = use_chat_id or value
        if normalized in ("thread", "topic"):
            use_thread_id = use_thread_id or value

    return (use_app, use_chat_id, use_thread_id)


def _resolve_scope_from_args(args: argparse.Namespace) -> dict[str, Optional[str]]:
    session_key = (getattr(args, "session_key", None) or "").strip() or None
    chat_app, chat_id, thread_id = _coalesce_scope_from_session_key(
        session_key,
        chat_app=getattr(args, "chat_app", None),
        chat_id=getattr(args, "chat_id", None),
        thread_id=getattr(args, "thread_id", None),
    )
    return {
        "session_key": session_key,
        "chat_app": (chat_app or "").strip() or None,
        "chat_id": (chat_id or "").strip() or None,
        "thread_id": (thread_id or "").strip() or None,
    }


def _build_message_scope_sql(
    scope: dict[str, Optional[str]],
    *,
    alias: str,
) -> tuple[str, list[Any]]:
    where: list[str] = []
    params: list[Any] = []

    thread_id = (scope.get("thread_id") or "").strip()
    chat_app = (scope.get("chat_app") or "").strip()
    chat_id = (scope.get("chat_id") or "").strip()
    session_key = (scope.get("session_key") or "").strip()

    if thread_id:
        where.append(f"{alias}.thread_id = ?")
        params.append(thread_id)
    if chat_app:
        where.append(f"{alias}.chat_app = ?")
        params.append(chat_app)
    if chat_id:
        where.append(f"{alias}.chat_id = ?")
        params.append(chat_id)
    if not where and session_key:
        where.append(f"{alias}.session_key = ?")
        params.append(session_key)

    if not where:
        return ("", [])
    return (" AND ".join(where), params)


def _build_event_scope_sql(scope: dict[str, Optional[str]]) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    origin_where, origin_params = _build_message_scope_sql(scope, alias="m")
    if origin_where:
        clauses.append(f"({origin_where})")
        params.extend(origin_params)

    session_key = (scope.get("session_key") or "").strip()
    if session_key:
        clauses.append("e.session_key = ?")
        params.append(session_key)

    if not clauses:
        return ("", [])
    return ("(" + " OR ".join(clauses) + ")", params)


def _serialize_scope(scope: dict[str, Optional[str]]) -> dict[str, Optional[str]]:
    return {
        "session_key": scope.get("session_key"),
        "chat_app": scope.get("chat_app"),
        "chat_id": scope.get("chat_id"),
        "thread_id": scope.get("thread_id"),
        "conversation_key": _build_conversation_key(
            scope.get("chat_app"),
            scope.get("chat_id"),
            scope.get("thread_id"),
        ),
    }


def _row_to_recall_result(row: sqlite3.Row) -> dict[str, Any]:
    item_type = str(row["item_type"] or "").strip() or "message"
    chat_app = (row["chat_app"] or "").strip() or None
    chat_id = (row["chat_id"] or "").strip() or None
    thread_id = (row["thread_id"] or "").strip() or None
    result: dict[str, Any] = {
        "type": item_type,
        "id": int(row["id"]),
        "ts_ms": int(row["ts_ms"]),
        "ts": _fmt_ts(int(row["ts_ms"])),
        "text": _normalize_recall_text(row["text"] or ""),
        "source_file": row["source_file"],
        "source_line": int(row["source_line"]),
        "session_id": (row["session_id"] or "").strip() or None,
        "session_key": (row["session_key"] or "").strip() or None,
        "chat_app": chat_app,
        "chat_id": chat_id,
        "thread_id": thread_id,
        "conversation_key": _build_conversation_key(chat_app, chat_id, thread_id),
    }
    if item_type == "message":
        result["author_role"] = (row["author_role"] or "").strip() or None
        result["author_name"] = (row["author_name"] or "").strip() or None
    else:
        result["kind"] = (row["kind"] or "").strip() or None
        result["name"] = (row["name"] or "").strip() or None
        rank = row["rank"]
        if rank is not None:
            result["rank"] = float(rank)
    return result


def _compile_fts_query(raw_query: str) -> str:
    raw = (raw_query or "").strip()
    if not raw:
        return ""
    tokens = re.findall(r"[A-Za-z0-9_:@./#-]{2,}", raw)
    if not tokens:
        return ""
    return " OR ".join([f'"{token}"' for token in tokens[:12]])


def _synthetic_learned_source_file(ts_ms: int) -> str:
    day = _date_iso_from_ts_ms(ts_ms)
    return f"memdb://learned/{day}.jsonl"


def cmd_last(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)
    rows = con.execute(
        """
        SELECT ts_ms, author_role, text, source_file, source_line
        FROM messages
        WHERE text IS NOT NULL AND length(text) > 0
        ORDER BY ts_ms DESC, id DESC
        LIMIT ?
        """,
        (args.n,),
    ).fetchall()

    for r in reversed(rows):
        print(f"[{_fmt_ts(int(r['ts_ms']))}] {r['author_role']}: {r['text']}")
        if args.show_source:
            print(f"  src: {r['source_file']}:{r['source_line']}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)

    q = args.query
    limit = args.n

    msg_hits = con.execute(
        """
        SELECT m.ts_ms, m.author_role, m.text, m.source_file, m.source_line,
               bm25(messages_fts) AS rank
        FROM messages_fts
        JOIN messages m ON m.id = messages_fts.rowid
        WHERE messages_fts MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (q, limit),
    ).fetchall()

    evt_hits = con.execute(
        """
        SELECT e.ts_ms, e.kind, e.name, e.text, e.source_file, e.source_line,
               bm25(events_fts) AS rank
        FROM events_fts
        JOIN events e ON e.id = events_fts.rowid
        WHERE events_fts MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (q, limit),
    ).fetchall()

    print("-- messages --")
    for r in msg_hits:
        print(f"[{_fmt_ts(int(r['ts_ms']))}] {r['author_role']}: {r['text']}")
        print(f"  src: {r['source_file']}:{r['source_line']} (rank={float(r['rank']):.3f})")

    print("\n-- events --")
    for r in evt_hits:
        label = f"{r['kind']}" + (f"/{r['name']}" if r['name'] else "")
        txt = r["text"] or ""
        if len(txt) > 400:
            txt = txt[:400] + "…"
        print(f"[{_fmt_ts(int(r['ts_ms']))}] {label}: {txt}")
        print(f"  src: {r['source_file']}:{r['source_line']} (rank={float(r['rank']):.3f})")

    return 0


def cmd_recent(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)

    scope = _resolve_scope_from_args(args)
    limit = max(1, int(args.n))
    include_events = bool(getattr(args, "include_events", False))

    message_where, message_params = _build_message_scope_sql(scope, alias="m")
    if not message_where:
        message_where = "1=1"
        message_params = []
    message_sql = f"""
        SELECT
          'message' AS item_type,
          m.id,
          m.ts_ms,
          m.session_id,
          m.session_key,
          m.chat_app,
          m.chat_id,
          m.thread_id,
          m.author_role,
          m.author_name,
          NULL AS kind,
          NULL AS name,
          m.text,
          m.source_file,
          m.source_line,
          NULL AS rank
        FROM messages m
        WHERE {message_where}
          AND m.text IS NOT NULL
          AND length(m.text) > 0
          AND COALESCE(m.author_role, '') != 'toolResult'
    """

    union_parts = [message_sql]
    params: list[Any] = list(message_params)
    if include_events:
        event_where, event_params = _build_event_scope_sql(scope)
        if not event_where:
            event_where = "1=1"
            event_params = []
        event_sql = f"""
            SELECT
              'event' AS item_type,
              e.id,
              e.ts_ms,
              e.session_id,
              e.session_key,
              m.chat_app,
              m.chat_id,
              m.thread_id,
              NULL AS author_role,
              NULL AS author_name,
              e.kind,
              e.name,
              e.text,
              e.source_file,
              e.source_line,
              NULL AS rank
            FROM events e
            LEFT JOIN messages m ON m.id = e.origin_message_id
            WHERE {event_where}
        """
        union_parts.append(event_sql)
        params.extend(event_params)

    sql = (
        "SELECT * FROM ("
        + " UNION ALL ".join(union_parts)
        + ") recent_items ORDER BY ts_ms DESC, id DESC LIMIT ?"
    )
    rows = con.execute(sql, tuple([*params, limit])).fetchall()
    payload = {
        "scope": _serialize_scope(scope),
        "results": [_row_to_recall_result(r) for r in reversed(rows)],
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)

    raw_query = (args.query or "").strip()
    if not raw_query:
        print("--query is required", file=sys.stderr)
        return 2

    scope = _resolve_scope_from_args(args)
    limit = max(1, int(args.n))
    include_events = bool(getattr(args, "include_events", False))

    fts_query = raw_query
    msg_where, msg_scope_params = _build_message_scope_sql(scope, alias="m")
    if not msg_where:
        msg_where = "1=1"
        msg_scope_params = []

    evt_where, evt_scope_params = _build_event_scope_sql(scope)
    if not evt_where:
        evt_where = "1=1"
        evt_scope_params = []

    def run_query(match_query: str) -> list[sqlite3.Row]:
        message_sql = f"""
            SELECT
              'message' AS item_type,
              m.id,
              m.ts_ms,
              m.session_id,
              m.session_key,
              m.chat_app,
              m.chat_id,
              m.thread_id,
              m.author_role,
              m.author_name,
              NULL AS kind,
              NULL AS name,
              m.text,
              m.source_file,
              m.source_line,
              bm25(messages_fts) AS rank
            FROM messages_fts
            JOIN messages m ON m.id = messages_fts.rowid
            WHERE messages_fts MATCH ?
              AND {msg_where}
              AND COALESCE(m.author_role, '') != 'toolResult'
        """

        union_parts = [message_sql]
        params: list[Any] = [match_query, *msg_scope_params]
        if include_events:
            event_sql = f"""
                SELECT
                  'event' AS item_type,
                  e.id,
                  e.ts_ms,
                  e.session_id,
                  e.session_key,
                  m.chat_app,
                  m.chat_id,
                  m.thread_id,
                  NULL AS author_role,
                  NULL AS author_name,
                  e.kind,
                  e.name,
                  e.text,
                  e.source_file,
                  e.source_line,
                  bm25(events_fts) AS rank
                FROM events_fts
                JOIN events e ON e.id = events_fts.rowid
                LEFT JOIN messages m ON m.id = e.origin_message_id
                WHERE events_fts MATCH ?
                  AND {evt_where}
            """
            union_parts.append(event_sql)
            params.extend([match_query, *evt_scope_params])

        sql = (
            "SELECT * FROM ("
            + " UNION ALL ".join(union_parts)
            + ") search_hits ORDER BY rank ASC, ts_ms DESC, id DESC LIMIT ?"
        )
        return con.execute(sql, tuple([*params, limit])).fetchall()

    try:
        rows = run_query(fts_query)
    except sqlite3.OperationalError:
        compiled = _compile_fts_query(raw_query)
        if not compiled:
            print(json.dumps({"query": raw_query, "scope": _serialize_scope(scope), "results": []}, indent=2))
            return 0
        rows = run_query(compiled)

    payload = {
        "query": raw_query,
        "scope": _serialize_scope(scope),
        "results": [_row_to_recall_result(r) for r in rows],
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_learn(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)

    title = (args.title or "").strip()
    if not title:
        print("--title is required", file=sys.stderr)
        return 2

    ts_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
    if args.timestamp:
        ts_ms = _utc_ms_from_iso(args.timestamp)
        if ts_ms <= 0:
            print(f"Invalid --timestamp: {args.timestamp}", file=sys.stderr)
            return 2

    memory_type = (args.memory_type or "").strip().lower()
    if memory_type not in LEARNED_MEMORY_TYPES:
        print(f"Unsupported --type: {memory_type}", file=sys.stderr)
        return 2

    summary = (args.summary or title).strip()
    key = _slugify((args.key or title).strip())
    tags = _normalize_string_list(args.tag)
    source_refs = _normalize_string_list(args.source_ref)
    evidence = _normalize_string_list(args.evidence)
    priority = (args.priority or "").strip().lower() or _default_priority_for_memory_type(memory_type)
    if priority not in ("red", "yellow", "green"):
        print(f"Unsupported --priority: {priority}", file=sys.stderr)
        return 2

    conversation: dict[str, str] = {}
    if args.chat_app:
        conversation["chat_app"] = args.chat_app.strip()
    if args.chat_id:
        conversation["chat_id"] = args.chat_id.strip()
    if args.thread_id:
        conversation["thread_id"] = args.thread_id.strip()
    if args.session_key:
        derived_app, derived_chat_id, derived_thread_id = _coalesce_scope_from_session_key(
            args.session_key,
            chat_app=conversation.get("chat_app"),
            chat_id=conversation.get("chat_id"),
            thread_id=conversation.get("thread_id"),
        )
        if derived_app:
            conversation["chat_app"] = derived_app
        if derived_chat_id:
            conversation["chat_id"] = derived_chat_id
        if derived_thread_id:
            conversation["thread_id"] = derived_thread_id

    payload: dict[str, Any] = {
        "schema": "memdb.learned.v1",
        "memory_type": memory_type,
        "key": key,
        "title": title,
        "summary": summary,
        "priority": priority,
        "tags": tags,
        "source_refs": source_refs,
        "evidence": evidence,
    }
    if args.session_id:
        payload["session_id"] = args.session_id.strip()
    if args.session_key:
        payload["session_key"] = args.session_key.strip()
    if conversation:
        payload["conversation"] = conversation

    text_lines = [f"{memory_type}: {title}"]
    if summary and summary != title:
        text_lines.append(summary)
    if tags:
        text_lines.append(f"tags: {', '.join(tags)}")

    event_id = _insert_event(
        con,
        source_file=_synthetic_learned_source_file(ts_ms),
        source_line=int(ts_ms % 2_147_483_647) or 1,
        ts_ms=ts_ms,
        session_id=(args.session_id or "").strip() or None,
        session_key=(args.session_key or "").strip() or None,
        origin_message_id=args.origin_message_id,
        kind="learned",
        name=memory_type,
        input_json=payload,
        output_json=None,
        text="\n".join(text_lines),
        raw_obj={
            "type": "learned",
            "schema": "memdb.learned.v1",
            "payload": payload,
        },
    )
    con.commit()

    print(
        json.dumps(
            {
                "id": event_id,
                "kind": "learned",
                "memory_type": memory_type,
                "key": key,
                "title": title,
                "source_file": _synthetic_learned_source_file(ts_ms),
            },
            indent=2,
        )
    )
    return 0


# -------------------------
# Vault build (memdb → Obsidian-compatible markdown vault)
# -------------------------

def _slugify(s: str) -> str:
    s = (s or "").strip().lower()
    out = []
    prev_dash = False
    for ch in s:
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        else:
            if not prev_dash:
                out.append("-")
                prev_dash = True
    slug = "".join(out).strip("-")
    return slug or "note"


def _vault_write(path: str, content: str) -> None:
    _ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _yaml_escape(s: str) -> str:
    s = (s or "").replace("\n", " ").strip()
    s = s.replace('"', "\\\"")
    return s


def _vault_note(
    *,
    title: str,
    memory_type: str,
    date_iso: str,
    priority: str = "yellow",
    tags: Optional[list[str]] = None,
    sources: Optional[list[str]] = None,
    body: str,
) -> str:
    tags = tags or []
    sources = sources or []
    fm = [
        "---",
        f'title: "{_yaml_escape(title)}"',
        f"memoryType: {memory_type}",
        f"priority: {priority}",
        f"created: {date_iso}",
        f"updated: {date_iso}",
        f"tags: {json.dumps(tags, ensure_ascii=False)}",
        f"sources: {json.dumps(sources, ensure_ascii=False)}",
        "---",
        "",
    ]
    return "\n".join(fm) + body.rstrip() + "\n"


def _date_iso_from_ts_ms(ts_ms: int) -> str:
    if not ts_ms:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return dt.datetime.fromtimestamp(ts_ms / 1000, tz=dt.timezone.utc).date().isoformat()


def _iter_messages_in_range(
    con: sqlite3.Connection,
    *,
    since_ms: Optional[int],
    until_ms: Optional[int],
) -> Iterable[sqlite3.Row]:
    where = []
    params: list[Any] = []
    if since_ms is not None:
        where.append("ts_ms >= ?")
        params.append(int(since_ms))
    if until_ms is not None:
        where.append("ts_ms < ?")
        params.append(int(until_ms))
    wsql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
        SELECT id, ts_ms, session_key, session_id, chat_app, chat_id, thread_id, author_role, text, raw_json
        FROM messages
        {wsql}
        AND text IS NOT NULL AND length(text) > 0
        ORDER BY ts_ms ASC, id ASC
    """ if where else """
        SELECT id, ts_ms, session_key, session_id, chat_app, chat_id, thread_id, author_role, text, raw_json
        FROM messages
        WHERE text IS NOT NULL AND length(text) > 0
        ORDER BY ts_ms ASC, id ASC
    """
    for r in con.execute(sql, tuple(params)).fetchall():
        yield r


def _iter_events_in_range(
    con: sqlite3.Connection,
    *,
    since_ms: Optional[int],
    until_ms: Optional[int],
    kinds: Optional[list[str]] = None,
) -> Iterable[sqlite3.Row]:
    where = []
    params: list[Any] = []
    if since_ms is not None:
        where.append("ts_ms >= ?")
        params.append(int(since_ms))
    if until_ms is not None:
        where.append("ts_ms < ?")
        params.append(int(until_ms))
    if kinds:
        placeholders = ",".join(["?"] * len(kinds))
        where.append(f"kind IN ({placeholders})")
        params.extend(kinds)

    wsql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
        SELECT id, ts_ms, session_key, session_id, origin_message_id, kind, name, input_json, output_json, text, raw_json
        FROM events
        {wsql}
        ORDER BY ts_ms ASC, id ASC
    """
    for r in con.execute(sql, tuple(params)).fetchall():
        yield r


def _obs_key(r: sqlite3.Row) -> str:
    # Prefer normalized chat routing if available.
    app = (r["chat_app"] or "").strip() or None
    chat_id = (r["chat_id"] or "").strip() or None
    thread_id = (r["thread_id"] or "").strip() or None

    if app and chat_id:
        if thread_id:
            return f"{app}:{chat_id}:topic:{thread_id}"
        return f"{app}:{chat_id}"

    # Fallback: session scoping.
    return (r["session_key"] or r["session_id"] or "unknown").strip()


def _extract_learned_event(row: sqlite3.Row) -> Optional[dict[str, Any]]:
    kind = (row["kind"] or "").strip().lower()
    name = (row["name"] or "").strip().lower()
    if kind != "learned" and not (kind == "custom" and name == "learned"):
        return None

    payload = _load_json_object(row["input_json"])
    raw_payload = _load_json_object(row["raw_json"])
    nested_payload = raw_payload.get("payload") if isinstance(raw_payload.get("payload"), dict) else None
    if not payload and nested_payload:
        payload = nested_payload
    if not payload and raw_payload.get("schema") == "memdb.learned.v1":
        payload = raw_payload

    memory_type = str(payload.get("memory_type") or "").strip().lower()
    if not memory_type and kind == "learned" and name in LEARNED_MEMORY_TYPES:
        memory_type = name
    if memory_type not in LEARNED_MEMORY_TYPES:
        return None

    title = str(payload.get("title") or "").strip()
    summary = str(payload.get("summary") or row["text"] or title).strip()
    if not title:
        title = summary or f"{memory_type.title()} memory"
    key = _slugify(str(payload.get("key") or title).strip())

    conversation = payload.get("conversation")
    if not isinstance(conversation, dict):
        conversation = {}

    chat_app = str(conversation.get("chat_app") or payload.get("chat_app") or "").strip() or None
    chat_id = str(conversation.get("chat_id") or payload.get("chat_id") or "").strip() or None
    thread_id = str(conversation.get("thread_id") or payload.get("thread_id") or "").strip() or None
    conversation_key = _build_conversation_key(chat_app, chat_id, thread_id)

    priority = str(payload.get("priority") or "").strip().lower()
    if priority not in ("red", "yellow", "green"):
        priority = _default_priority_for_memory_type(memory_type)

    return {
        "memory_type": memory_type,
        "key": key,
        "title": title,
        "summary": summary,
        "priority": priority,
        "tags": _normalize_string_list(payload.get("tags")),
        "source_refs": _normalize_string_list(payload.get("source_refs")),
        "evidence": _normalize_string_list(payload.get("evidence")),
        "session_id": str(payload.get("session_id") or row["session_id"] or "").strip() or None,
        "session_key": str(payload.get("session_key") or row["session_key"] or "").strip() or None,
        "conversation_key": conversation_key,
    }


def _extract_typed_items(*, author_role: str | None, text: str) -> list[tuple[str, str]]:
    """Return list of (type, payload) from a message text using **very conservative** heuristics.

    We bias toward precision to avoid vault spam.

    Rules:
    - Only treat explicit markers as typed memories (Decision:/Preference:/Rule:/Lesson:)
    - Plus a small set of clear preference/commitment phrases.
    """
    out: list[tuple[str, str]] = []
    t = (text or "").strip()
    if not t:
        return out

    low = t.lower()
    role = (author_role or "").lower()

    # Explicit typed markers (any role)
    if low.startswith("decision:"):
        out.append(("decision", t))
        return out
    if low.startswith("preference:"):
        out.append(("preference", t))
        return out
    if low.startswith("commitment:"):
        out.append(("commitment", t))
        return out
    if low.startswith("lesson:") or low.startswith("rule:"):
        out.append(("lesson", t))
        return out

    # Light heuristics (user messages only)
    if role == "user":
        if low.startswith("i prefer ") or low.startswith("i like "):
            out.append(("preference", t))
        if low.startswith("remind me"):
            out.append(("commitment", t))

        # Decisions often start as "let's/lets".
        if low.startswith("let's ") or low.startswith("lets "):
            out.append(("decision", t))

        # Simple policy/rule statements.
        if ("never " in low or low.startswith("never ") or low.startswith("always ")) and len(t) <= 240:
            out.append(("lesson", t))

    return out


def _vault_prune_legacy_artifacts(vault_dir: str) -> dict[str, int]:
    removed_files = 0
    removed_dirs = 0

    for rel_dir in ("observations", "threads"):
        path = os.path.join(vault_dir, rel_dir)
        if os.path.isdir(path):
            shutil.rmtree(path)
            removed_dirs += 1

    for root, _dirs, files in os.walk(vault_dir):
        for fn in files:
            if not fn.endswith(".json"):
                rel_root = os.path.relpath(root, vault_dir)
                if rel_root in TYPED_VAULT_DIRS and _LEGACY_VAULT_ROLLUP_RE.match(fn):
                    os.remove(os.path.join(root, fn))
                    removed_files += 1
                elif rel_root == "." and fn == "inbox.md":
                    os.remove(os.path.join(root, fn))
                    removed_files += 1
                continue
            os.remove(os.path.join(root, fn))
            removed_files += 1

    return {"files": removed_files, "dirs": removed_dirs}


def _vault_clean_target(vault_dir: str) -> dict[str, int]:
    removed_files = 0
    removed_dirs = 0

    for rel_dir in TYPED_VAULT_DIRS:
        path = os.path.join(vault_dir, rel_dir)
        if os.path.isdir(path):
            shutil.rmtree(path)
            removed_dirs += 1

    for rel_file in ("index.md", "inbox.md"):
        path = os.path.join(vault_dir, rel_file)
        if os.path.exists(path):
            os.remove(path)
            removed_files += 1

    pruned = _vault_prune_legacy_artifacts(vault_dir)
    return {
        "files": removed_files + pruned["files"],
        "dirs": removed_dirs + pruned["dirs"],
    }


INBOX_ALLOWED_CATEGORIES = {
    "commitments",
    "decisions",
    "handoffs",
    "inbox",
    "lessons",
    "people",
    "preferences",
    "projects",
}

INBOX_BANNED_MARKERS = (
    "[cron:",
    "current time:",
    "return your summary as plain text",
    "toolresult",
    "**assistant**",
    "**user**",
    "memory/vault/threads/",
    "memory/vault/observations/",
    "stats:",
    "tokens ",
    "process exited with code",
    "sessionkey agent:",
    "transcript /root/.openclaw",
    "summarize this naturally",
    "a cron job \"",
    "subagent task",
    "conversation info (untrusted metadata)",
)

_INBOX_SECTION_RE = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})")
_INBOX_KEY_LINE_RE = re.compile(
    r"^key=(?P<key>\S+)\s+category=(?P<category>[a-z]+)\s+claim=(?P<claim>.+?)(?:\s+\(query=(?P<query>.+?)\))?$",
    re.IGNORECASE,
)
_INBOX_POSSIBLE_LINE_RE = re.compile(
    r"^Possible\s+(?P<claim>.+?)(?:\s+Evidence:\s*(?P<evidence>.+))?$",
    re.IGNORECASE,
)
_INBOX_TYPED_LINE_RE = re.compile(r"^\[(?P<category>[a-z]+)\]\s+(?P<claim>.+)$", re.IGNORECASE)


def _iter_inbox_section_blocks(text: str) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    current_section = "Undated"
    current_block: list[str] = []

    def flush_block() -> None:
        nonlocal current_block
        if current_block:
            blocks.append((current_section, current_block))
            current_block = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        section_match = _INBOX_SECTION_RE.match(line.strip())
        if section_match:
            flush_block()
            current_section = section_match.group(1)
            continue
        if line.startswith("- "):
            flush_block()
            current_block = [line]
            continue
        if current_block:
            current_block.append(line)

    flush_block()
    return blocks


def _normalize_inbox_text(text: str) -> str:
    return " ".join((text or "").strip().split())


def _ensure_sentence(text: str) -> str:
    text = _normalize_inbox_text(text)
    if not text:
        return ""
    if text[-1] not in ".!?":
        return text + "."
    return text


def _contains_banned_inbox_marker(text: str) -> bool:
    low = (text or "").lower()
    return any(marker in low for marker in INBOX_BANNED_MARKERS)


def _clean_inbox_claim(category: str, claim: str) -> Optional[str]:
    cleaned = _normalize_inbox_text(claim)
    if not cleaned:
        return None
    if _contains_banned_inbox_marker(cleaned):
        return None
    if "?" in cleaned:
        return None

    words = cleaned.split()
    low = cleaned.lower()
    if category == "inbox":
        if len(words) < 8 and len(cleaned) < 48:
            return None
        if "/root/" in low:
            return None
        if re.match(r"^(ok[, ]|write this|in /root/|fetch |give me |report:|thread title:)", low):
            return None
        if not re.search(r"\b(possible|potential|appears|likely|maybe|might|risk|unclear|unknown|discussed?)\b", low):
            return None
    elif len(words) < 3:
        return None

    return _ensure_sentence(cleaned)


def _normalize_inbox_detail_lines(lines: list[str]) -> list[str]:
    kept: list[str] = []
    seen: set[str] = set()
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("- "):
            stripped = stripped[2:].strip()
        if _contains_banned_inbox_marker(stripped):
            continue

        lower = stripped.lower()
        if ":" not in stripped:
            continue
        label, value = stripped.split(":", 1)
        label = label.strip().lower()
        if label not in {"confidence", "evidence", "key", "query"}:
            continue

        value = _normalize_inbox_text(value)
        if not value:
            continue

        normalized = f"{label}:{value.lower()}"
        if normalized in seen:
            continue
        seen.add(normalized)
        kept.append(f"  - {label}: {value}")
    return kept


def _sanitize_inbox_block(lines: list[str]) -> Optional[str]:
    block = "\n".join(lines).strip()
    if not block or _contains_banned_inbox_marker(block):
        return None

    first_line = lines[0].strip()
    if not first_line.startswith("- "):
        return None
    body = _normalize_inbox_text(first_line[2:])
    details = _normalize_inbox_detail_lines(lines[1:])

    key_match = _INBOX_KEY_LINE_RE.match(body)
    if key_match:
        category = str(key_match.group("category") or "").strip().lower()
        if category not in INBOX_ALLOWED_CATEGORIES or category == "inbox":
            return None
        claim = _clean_inbox_claim(category, str(key_match.group("claim") or ""))
        if not claim:
            return None
        out = [f"- [{category}] {claim}"]
        key_value = _normalize_inbox_text(str(key_match.group("key") or ""))
        query_value = _normalize_inbox_text(str(key_match.group("query") or ""))
        if key_value:
            out.append(f"  - key: {key_value}")
        if query_value:
            out.append(f"  - query: {query_value}")
        out.extend(details)
        return "\n".join(out)

    possible_match = _INBOX_POSSIBLE_LINE_RE.match(body)
    if possible_match:
        claim = _clean_inbox_claim("inbox", f"Possible {str(possible_match.group('claim') or '').strip()}")
        if not claim:
            return None
        out = [f"- {claim}"]
        inline_evidence = _normalize_inbox_text(str(possible_match.group("evidence") or ""))
        if inline_evidence and not _contains_banned_inbox_marker(inline_evidence):
            out.append(f"  - evidence: {inline_evidence}")
        out.extend(details)
        return "\n".join(out)

    typed_match = _INBOX_TYPED_LINE_RE.match(body)
    if typed_match:
        category = str(typed_match.group("category") or "").strip().lower()
        if category not in INBOX_ALLOWED_CATEGORIES:
            return None
        claim = _clean_inbox_claim(category, str(typed_match.group("claim") or ""))
        if not claim:
            return None
        out = [f"- [{category}] {claim}"]
        out.extend(details)
        return "\n".join(out)

    return None


def _render_clean_inbox(sections: list[tuple[str, list[str]]]) -> str:
    lines = [
        "# Memory Inbox",
        "",
        "Low-confidence memory candidates that are not yet canonical typed notes.",
        "This file lives outside memory/vault on purpose so builtin vault search does not treat it as canonical memory.",
        "Keep only concise claims with direct evidence. No prompts, tool output, transcript dumps, or artifact paths.",
        "",
    ]

    for section, blocks in sections:
        if not blocks:
            continue
        lines.append(f"## {section}")
        for block in blocks:
            lines.extend(block.splitlines())
            lines.append("")

    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines) + "\n"


def cmd_vault_build(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)

    out_dir = os.path.abspath(args.out)
    vault_dir = out_dir
    if args.clean and not args.all:
        print("--clean currently requires --all to avoid deleting out-of-range notes", file=sys.stderr)
        return 2

    # Parse since/until
    since_ms: Optional[int] = None
    until_ms: Optional[int] = None
    if args.all:
        since_ms = None
        until_ms = None
    else:
        if args.since:
            # accept YYYY-MM-DD
            d = dt.date.fromisoformat(args.since)
            since_ms = int(dt.datetime(d.year, d.month, d.day, tzinfo=dt.timezone.utc).timestamp() * 1000)
        if args.until:
            d = dt.date.fromisoformat(args.until)
            until_ms = int(dt.datetime(d.year, d.month, d.day, tzinfo=dt.timezone.utc).timestamp() * 1000)

    cleaned = {"files": 0, "dirs": 0}
    if args.clean:
        cleaned = _vault_clean_target(vault_dir)

    # Ensure skeleton
    for subdir in TYPED_VAULT_DIRS:
        os.makedirs(os.path.join(vault_dir, subdir), exist_ok=True)

    typed_notes: dict[tuple[str, str], dict[str, Any]] = {}
    days: set[str] = set()
    for r in _iter_messages_in_range(con, since_ms=since_ms, until_ms=until_ms):
        day = _date_iso_from_ts_ms(int(r["ts_ms"]))
        days.add(day)
        key = _obs_key(r)
        role = r["author_role"] or "?"
        text = (r["text"] or "").strip()
        if not text:
            continue

        for typ, payload in _extract_typed_items(author_role=role, text=text):
            slug = _slugify(payload[:60])
            record = typed_notes.setdefault(
                (typ, slug),
                {
                    "title": f"{typ.title()}: {slug.replace('-', ' ')}",
                    "summary": None,
                    "priority": _default_priority_for_memory_type(typ),
                    "tags": {typ},
                    "sources": {"memdb"},
                    "evidence": [],
                },
            )
            evidence_line = f"- {day} ({key}): {payload}"
            if evidence_line not in record["evidence"]:
                record["evidence"].append(evidence_line)

    today = dt.date.today().isoformat()

    for r in _iter_events_in_range(con, since_ms=since_ms, until_ms=until_ms, kinds=["learned", "custom"]):
        learned = _extract_learned_event(r)
        if not learned:
            continue

        typ = learned["memory_type"]
        slug = learned["key"]
        record = typed_notes.setdefault(
            (typ, slug),
            {
                "title": learned["title"],
                "summary": None,
                "priority": learned["priority"],
                "tags": {typ, "learned"},
                "sources": {"memdb"},
                "evidence": [],
            },
        )
        record["title"] = learned["title"] or record["title"]
        if learned["summary"]:
            record["summary"] = learned["summary"]
        record["priority"] = learned["priority"] or record["priority"]
        record["tags"].update([typ, "learned", *learned["tags"]])
        record["sources"].update(["memdb", f"memdb:event:{int(r['id'])}"])
        record["sources"].update(learned["source_refs"])

        evidence_parts = [f"[{_fmt_ts(int(r['ts_ms']))}] learned event #{int(r['id'])}"]
        if learned["conversation_key"]:
            evidence_parts.append(f"conversation={learned['conversation_key']}")
        elif learned["session_key"]:
            evidence_parts.append(f"session={learned['session_key']}")
        if learned["source_refs"]:
            evidence_parts.append(f"refs={', '.join(learned['source_refs'])}")
        evidence_line = f"- {'; '.join(evidence_parts)} — {learned['summary'] or learned['title']}"
        if evidence_line not in record["evidence"]:
            record["evidence"].append(evidence_line)
        for extra in learned["evidence"]:
            extra_line = f"- Evidence: {extra}"
            if extra_line not in record["evidence"]:
                record["evidence"].append(extra_line)

    # Generate typed notes (deterministic overwrite)
    for (typ, slug), meta in sorted(typed_notes.items()):
        dname = TYPE_TO_DIR.get(typ)
        if not dname:
            continue
        title = meta["title"] or f"{typ.title()}: {slug.replace('-', ' ')}"
        body_lines = [f"# {title}", "", "(Generated from memdb; do not edit)", ""]
        summary = (meta.get("summary") or "").strip()
        if summary:
            body_lines.extend(["## Summary", "", summary, ""])
        body_lines.extend(["## Evidence", ""])
        evidence_lines = list(meta.get("evidence") or [])
        body_lines.extend(evidence_lines or ["- No evidence captured."])
        body = "\n".join(body_lines) + "\n"
        note = _vault_note(
            title=title,
            memory_type=typ,
            date_iso=today,
            priority=meta.get("priority") or _default_priority_for_memory_type(typ),
            tags=sorted(meta.get("tags") or [typ]),
            sources=sorted(meta.get("sources") or ["memdb"]),
            body=body,
        )
        path = os.path.join(vault_dir, dname, f"{slug}.md")
        _vault_write(path, note)

    # Rebuild index.md
    index_lines = [
        "# Vault Index",
        "",
        "(Generated; do not edit)",
        "",
        "| Note | Type | Priority |",
        "|------|------|----------|",
    ]

    for root, _, files in os.walk(vault_dir):
        rel_root = os.path.relpath(root, vault_dir)
        if rel_root == ".":
            rel_root = ""
        for fn in sorted([f for f in files if f.endswith(".md") and f != "index.md"]):
            rel = os.path.join(rel_root, fn).lstrip("./")
            # naive parse: read first 25 lines and pick memoryType/priority
            fpath = os.path.join(vault_dir, rel)
            mtype = "?"
            prio = "?"
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    head_lines = []
                    for _ in range(60):
                        line = f.readline()
                        if not line:
                            break
                        head_lines.append(line)
                for line in "".join(head_lines).splitlines():
                    if line.startswith("memoryType:"):
                        mtype = line.split(":", 1)[1].strip()
                    if line.startswith("priority:"):
                        prio = line.split(":", 1)[1].strip()
            except Exception:
                pass
            index_lines.append(f"| [{rel}]({rel}) | {mtype} | {prio} |")

    _vault_write(os.path.join(vault_dir, "index.md"), "\n".join(index_lines) + "\n")

    pruned = _vault_prune_legacy_artifacts(vault_dir)
    print(
        json.dumps(
            {
                "out": vault_dir,
                "days": len(days),
                "typed_notes": len(typed_notes),
                "cleaned": cleaned,
                "pruned": pruned,
            },
            indent=2,
        )
    )
    return 0


def cmd_backfill_chat(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)

    # Pass 1: infer on rows with raw JSON. Prefer raw_json (more likely to
    # contain metadata than flattened text), and use source_file as a fallback
    # for Treechat topic/thread ids.
    rows = con.execute(
        """
        SELECT id, session_id, session_key, source_file, raw_json
        FROM messages
        WHERE raw_json IS NOT NULL
        ORDER BY id ASC
        """
    ).fetchall()

    updated_direct = 0
    # Also build a per-session map so we can propagate to adjacent rows in the same session.
    session_map: dict[str, tuple[Optional[str], Optional[str], Optional[str]]] = {}

    for r in rows:
        app, chat_id, thread_id = _infer_chat_fields_from_text(
            r["raw_json"] or "",
            source_file=r["source_file"],
        )
        if app or chat_id or thread_id:
            con.execute(
                "UPDATE messages SET chat_app=COALESCE(chat_app, ?), chat_id=COALESCE(chat_id, ?), thread_id=COALESCE(thread_id, ?) WHERE id=?",
                (app, chat_id, thread_id, int(r["id"])),
            )
            updated_direct += 1

            sid = (r["session_id"] or r["session_key"] or "").strip()
            if sid:
                prev_app, prev_chat_id, prev_thread_id = session_map.get(sid, (None, None, None))
                session_map[sid] = (
                    app or prev_app,
                    chat_id or prev_chat_id,
                    thread_id or prev_thread_id,
                )

    # Pass 2: propagate inferred chat/thread scope within the same session.
    updated_propagated = 0
    for sid, (app, chat_id, thread_id) in session_map.items():
        if not (app or chat_id or thread_id):
            continue
        cur = con.execute(
            """
            UPDATE messages
            SET chat_app=COALESCE(chat_app, ?), chat_id=COALESCE(chat_id, ?), thread_id=COALESCE(thread_id, ?)
            WHERE (session_id = ? OR session_key = ?)
              AND (
                chat_app IS NULL OR chat_app = ''
                OR chat_id IS NULL OR chat_id = ''
                OR thread_id IS NULL OR thread_id = ''
              )
            """,
            (app, chat_id, thread_id, sid, sid),
        )
        updated_propagated += int(cur.rowcount or 0)

    con.commit()
    print(
        json.dumps(
            {
                "rows_scanned": len(rows),
                "rows_updated_direct": updated_direct,
                "sessions_with_chat": len(session_map),
                "rows_updated_propagated": updated_propagated,
            },
            indent=2,
        )
    )
    return 0


def cmd_inbox_clean(args: argparse.Namespace) -> int:
    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"Missing inbox file: {path}", file=sys.stderr)
        return 2

    with open(path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    raw_blocks = _iter_inbox_section_blocks(raw_text)
    grouped: dict[str, list[str]] = {}
    section_order: list[str] = []
    seen: set[str] = set()

    total_blocks = 0
    kept_blocks = 0
    dropped_blocks = 0
    deduped_blocks = 0

    for section, block_lines in raw_blocks:
        total_blocks += 1
        cleaned = _sanitize_inbox_block(block_lines)
        if not cleaned:
            dropped_blocks += 1
            continue

        signature = _normalize_inbox_text(cleaned).lower()
        if signature in seen:
            deduped_blocks += 1
            continue
        seen.add(signature)

        if section not in grouped:
            grouped[section] = []
            section_order.append(section)
        grouped[section].append(cleaned)
        kept_blocks += 1

    rendered = _render_clean_inbox([(section, grouped.get(section, [])) for section in section_order])
    if args.write:
        _vault_write(path, rendered)

    print(
        json.dumps(
            {
                "path": path,
                "write": bool(args.write),
                "total_blocks": total_blocks,
                "kept_blocks": kept_blocks,
                "dropped_blocks": dropped_blocks,
                "deduped_blocks": deduped_blocks,
                "sections": section_order,
            },
            indent=2,
        )
    )
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    con = connect(args.db)
    init_db(con)
    print(f"OK: initialized {args.db}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="memdb")
    p.add_argument("--db", default=os.environ.get("MEMDB_PATH", "/root/clawd/memory/memdb.sqlite3"))

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("ingest", help="Ingest OpenClaw session .jsonl files (glob patterns allowed)")
    sp.add_argument("paths", nargs="+", help="Paths/globs (use quotes), e.g. '/root/.openclaw/agents/**/sessions/*.jsonl'")
    sp.add_argument("--force", action="store_true")
    sp.add_argument("--chat-app", default=None, help="Optional: force chat_app value (e.g. telegram)")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("last")
    sp.add_argument("-n", type=int, default=20)
    sp.add_argument("--show-source", action="store_true")
    sp.set_defaults(func=cmd_last)

    sp = sub.add_parser("search")
    sp.add_argument("query")
    sp.add_argument("-n", type=int, default=10)
    sp.set_defaults(func=cmd_search)

    sp = sub.add_parser("recent", help="Fetch recent memdb messages/events for the current scoped conversation")
    sp.add_argument("-n", type=int, default=20)
    sp.add_argument("--include-events", action="store_true")
    sp.add_argument("--session-key", default=None)
    sp.add_argument("--chat-app", default=None)
    sp.add_argument("--chat-id", default=None)
    sp.add_argument("--thread-id", default=None)
    sp.set_defaults(func=cmd_recent)

    sp = sub.add_parser("query", help="Search memdb messages/events with optional conversation scope")
    sp.add_argument("query")
    sp.add_argument("-n", type=int, default=10)
    sp.add_argument("--include-events", action="store_true")
    sp.add_argument("--session-key", default=None)
    sp.add_argument("--chat-app", default=None)
    sp.add_argument("--chat-id", default=None)
    sp.add_argument("--thread-id", default=None)
    sp.set_defaults(func=cmd_query)

    sp = sub.add_parser("learn", help="Record an explicit durable learning event in memdb")
    sp.add_argument("--type", dest="memory_type", required=True, choices=sorted(LEARNED_MEMORY_TYPES))
    sp.add_argument("--title", required=True)
    sp.add_argument("--summary", default=None, help="Short durable summary; defaults to title")
    sp.add_argument("--key", default=None, help="Stable key/slug; defaults to slugified title")
    sp.add_argument("--priority", choices=["red", "yellow", "green"], default=None)
    sp.add_argument("--tag", action="append", default=[], help="Repeatable tag")
    sp.add_argument("--source-ref", action="append", default=[], help="Repeatable source reference")
    sp.add_argument("--evidence", action="append", default=[], help="Repeatable evidence snippet")
    sp.add_argument("--session-id", default=None)
    sp.add_argument("--session-key", default=None)
    sp.add_argument("--chat-app", default=None)
    sp.add_argument("--chat-id", default=None)
    sp.add_argument("--thread-id", default=None)
    sp.add_argument("--origin-message-id", type=int, default=None)
    sp.add_argument("--timestamp", default=None, help="ISO timestamp, e.g. 2026-03-13T12:00:00Z")
    sp.set_defaults(func=cmd_learn)

    sp = sub.add_parser("backfill-chat", help="Best-effort backfill chat_app/chat_id/thread_id from embedded conversation_label text")
    sp.set_defaults(func=cmd_backfill_chat)

    sp = sub.add_parser("inbox-clean", help="Prune junk from the vault inbox and normalize surviving entries")
    sp.add_argument("--path", default=DEFAULT_MEMORY_INBOX_PATH)
    sp.add_argument("--write", action="store_true")
    sp.set_defaults(func=cmd_inbox_clean)

    sp = sub.add_parser("vault-build", help="Generate Obsidian-compatible vault markdown from memdb")
    sp.add_argument("--out", default="/root/clawd/memory/vault")
    sp.add_argument("--all", action="store_true", help="Build from all time")
    sp.add_argument("--clean", action="store_true", help="Clean generated vault targets first (requires --all)")
    sp.add_argument("--since", default=None, help="YYYY-MM-DD (inclusive)")
    sp.add_argument("--until", default=None, help="YYYY-MM-DD (exclusive)")
    sp.add_argument("--max-per-conversation", type=int, default=80, help="Max messages to include per conversation section")
    sp.set_defaults(func=cmd_vault_build)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
