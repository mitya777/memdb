"""Provenance records for memdb writes: canonical hashing, signing, Merkle proofs, storage.

A provenance record is a small JSON object that says, for one memdb row:
  - the SHA-256 of the row's canonical content,
  - the source the *server* established for the write (never a caller-supplied field),
  - the channel evidence behind that source (e.g. a verified OpenAI mTLS client cert),
  - when memdb received it,
  - which attestation key signed it.

Records are signed with an Ed25519 attestation key and later committed, many at a
time, under one Merkle root written into a Bitcoin SV transaction (see anchor.py).

Storage is append-only: provenance rows live in their own tables next to `events`
and are guarded by triggers that abort UPDATE/DELETE. Existing memdb rows are never
rewritten.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import sqlite3
from typing import Any, Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RECORD_SCHEMA = "memdb.provenance.v1"
CONTENT_SCHEMA = "memdb.content.v1"
BUNDLE_SCHEMA = "memdb.proof-bundle.v1"

SOURCE_OPENAI = "openai"
SOURCE_UNVERIFIED = "unverified"


# ---------------------------------------------------------------------------
# Canonical encoding and hashing
# ---------------------------------------------------------------------------

def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def event_content(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Canonical content object for one `events` row (the part a reader cares about)."""
    raw_payload = row["input_json"]
    payload = json.loads(raw_payload) if raw_payload else None
    return {
        "schema": CONTENT_SCHEMA,
        "table": "events",
        "id": int(row["id"]),
        "ts_ms": int(row["ts_ms"]),
        "kind": row["kind"],
        "name": row["name"],
        "payload": payload,
        "text": row["text"],
    }


def content_hash(content: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(content))


def record_hash(record: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(record))


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Attestation key
# ---------------------------------------------------------------------------

class Attester:
    """Ed25519 attestation key held by the memdb server operator."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        self.public_key_hex = public_key_hex(private_key.public_key())

    @classmethod
    def generate(cls) -> "Attester":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_file(cls, path: str) -> "Attester":
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
        return cls(key)

    def write_pem(self, path: str) -> None:
        pem = self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)

    def sign(self, record: dict[str, Any]) -> str:
        return base64.b64encode(self._key.sign(canonical_json(record))).decode("ascii")


def public_key_hex(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def verify_signature(record: dict[str, Any], signature_b64: str, public_key: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        pub.verify(base64.b64decode(signature_b64, validate=True), canonical_json(record))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

def build_record(
    *,
    content: dict[str, Any],
    channel: dict[str, Any],
    authorization: dict[str, Any],
    attester_public_key: str,
    received_at: Optional[str] = None,
) -> dict[str, Any]:
    """Build the provenance record. `source` comes only from verified channel evidence."""
    source = SOURCE_OPENAI if channel.get("openai_verified") is True else SOURCE_UNVERIFIED
    return {
        "schema": RECORD_SCHEMA,
        "memory": {"table": content["table"], "id": content["id"]},
        "content_sha256": content_hash(content),
        "source": source,
        "channel": channel,
        "authorization": authorization,
        "received_at": received_at or utc_now_iso(),
        "attester": {"alg": "ed25519", "public_key": attester_public_key},
    }


# ---------------------------------------------------------------------------
# Merkle tree (RFC 6962-style domain separation)
# ---------------------------------------------------------------------------

def merkle_leaf(record_hash_hex: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(record_hash_hex)).digest()


def _merkle_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root_and_proofs(record_hashes: list[str]) -> tuple[str, list[list[dict[str, str]]]]:
    """Return (root_hex, proofs). proofs[i] is the inclusion path for leaf i.

    An odd node at the end of a level is promoted unchanged (no duplication), so a
    leaf can't be proven twice under different indices.
    """
    if not record_hashes:
        raise ValueError("cannot build a Merkle tree with no leaves")
    level = [merkle_leaf(h) for h in record_hashes]
    positions = [[i] for i in range(len(level))]  # leaves under each node
    proofs: list[list[dict[str, str]]] = [[] for _ in record_hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        next_positions: list[list[int]] = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):
                next_level.append(level[i])
                next_positions.append(positions[i])
                continue
            left, right = level[i], level[i + 1]
            for leaf_index in positions[i]:
                proofs[leaf_index].append({"side": "right", "hash": right.hex()})
            for leaf_index in positions[i + 1]:
                proofs[leaf_index].append({"side": "left", "hash": left.hex()})
            next_level.append(_merkle_node(left, right))
            next_positions.append(positions[i] + positions[i + 1])
        level, positions = next_level, next_positions
    return level[0].hex(), proofs


def merkle_root_from_proof(record_hash_hex: str, proof: Iterable[dict[str, str]]) -> str:
    node = merkle_leaf(record_hash_hex)
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        if step["side"] == "right":
            node = _merkle_node(node, sibling)
        elif step["side"] == "left":
            node = _merkle_node(sibling, node)
        else:
            raise ValueError(f"bad proof step side: {step['side']!r}")
    return node.hex()


# ---------------------------------------------------------------------------
# Storage (append-only, alongside memdb's `events`)
# ---------------------------------------------------------------------------

PROVENANCE_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS provenance_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER NOT NULL UNIQUE REFERENCES events(id),
  record_json TEXT NOT NULL,
  record_hash TEXT NOT NULL UNIQUE,
  signature TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS provenance_anchors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mode TEXT NOT NULL CHECK (mode IN ('dry-run', 'broadcast')),
  merkle_root TEXT NOT NULL,
  leaf_count INTEGER NOT NULL,
  txid TEXT NOT NULL,
  raw_tx TEXT NOT NULL,
  broadcast_response TEXT,
  created_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS provenance_anchor_leaves (
  anchor_id INTEGER NOT NULL REFERENCES provenance_anchors(id),
  leaf_index INTEGER NOT NULL,
  record_id INTEGER NOT NULL REFERENCES provenance_records(id),
  PRIMARY KEY (anchor_id, leaf_index)
);
CREATE INDEX IF NOT EXISTS idx_provenance_anchor_leaves_record ON provenance_anchor_leaves(record_id);

CREATE TRIGGER IF NOT EXISTS provenance_records_no_update BEFORE UPDATE ON provenance_records
BEGIN SELECT RAISE(ABORT, 'provenance_records is append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_records_no_delete BEFORE DELETE ON provenance_records
BEGIN SELECT RAISE(ABORT, 'provenance_records is append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_anchors_no_update BEFORE UPDATE ON provenance_anchors
BEGIN SELECT RAISE(ABORT, 'provenance_anchors is append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_anchors_no_delete BEFORE DELETE ON provenance_anchors
BEGIN SELECT RAISE(ABORT, 'provenance_anchors is append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_anchor_leaves_no_update BEFORE UPDATE ON provenance_anchor_leaves
BEGIN SELECT RAISE(ABORT, 'provenance_anchor_leaves is append-only'); END;
CREATE TRIGGER IF NOT EXISTS provenance_anchor_leaves_no_delete BEFORE DELETE ON provenance_anchor_leaves
BEGIN SELECT RAISE(ABORT, 'provenance_anchor_leaves is append-only'); END;

-- Attested memory rows keep their content. memdb's own migrations only touch
-- origin_message_id, which is not part of the attested content.
CREATE TRIGGER IF NOT EXISTS events_attested_no_content_update
BEFORE UPDATE OF ts_ms, kind, name, input_json, text ON events
WHEN EXISTS (SELECT 1 FROM provenance_records p WHERE p.event_id = old.id)
BEGIN SELECT RAISE(ABORT, 'attested memdb event is immutable'); END;
CREATE TRIGGER IF NOT EXISTS events_attested_no_delete
BEFORE DELETE ON events
WHEN EXISTS (SELECT 1 FROM provenance_records p WHERE p.event_id = old.id)
BEGIN SELECT RAISE(ABORT, 'attested memdb event is immutable'); END;
"""


def init_provenance(con: sqlite3.Connection) -> None:
    con.executescript(PROVENANCE_SCHEMA_SQL)
    con.commit()


def _now_ms() -> int:
    return int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)


def load_event(con: sqlite3.Connection, event_id: int) -> Optional[sqlite3.Row]:
    return con.execute(
        "SELECT id, ts_ms, kind, name, input_json, text FROM events WHERE id = ?",
        (int(event_id),),
    ).fetchone()


def attest_event(
    con: sqlite3.Connection,
    *,
    event_id: int,
    channel: dict[str, Any],
    authorization: dict[str, Any],
    attester: Attester,
) -> dict[str, Any]:
    """Create and store the signed provenance record for an existing event. No commit."""
    row = load_event(con, event_id)
    if row is None:
        raise LookupError(f"no events row with id {event_id}")
    content = event_content(row)
    record = build_record(
        content=content,
        channel=channel,
        authorization=authorization,
        attester_public_key=attester.public_key_hex,
    )
    signature = attester.sign(record)
    rhash = record_hash(record)
    con.execute(
        """
        INSERT INTO provenance_records(event_id, record_json, record_hash, signature, source, created_at_ms)
        VALUES (?,?,?,?,?,?)
        """,
        (int(event_id), canonical_json(record).decode("utf-8"), rhash, signature, record["source"], _now_ms()),
    )
    return {"record": record, "record_hash": rhash, "signature": signature}


def provenance_summary(con: sqlite3.Connection, event_ids: Iterable[int]) -> dict[int, dict[str, Any]]:
    """Short provenance labels for search results, keyed by event id."""
    ids = [int(i) for i in event_ids]
    if not ids:
        return {}
    marks = ",".join("?" for _ in ids)
    rows = con.execute(
        f"""
        SELECT p.event_id, p.source, p.record_hash,
          (SELECT a.txid FROM provenance_anchor_leaves l JOIN provenance_anchors a ON a.id = l.anchor_id
           WHERE l.record_id = p.id AND a.mode = 'broadcast' ORDER BY a.id DESC LIMIT 1) AS onchain_txid
        FROM provenance_records p WHERE p.event_id IN ({marks})
        """,
        ids,
    ).fetchall()
    return {
        int(r["event_id"]): {
            "source": r["source"],
            "record_hash": r["record_hash"],
            "anchored_txid": r["onchain_txid"],
        }
        for r in rows
    }


def unanchored_records(con: sqlite3.Connection, mode: str) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT p.id, p.record_hash FROM provenance_records p
        WHERE NOT EXISTS (
          SELECT 1 FROM provenance_anchor_leaves l JOIN provenance_anchors a ON a.id = l.anchor_id
          WHERE l.record_id = p.id AND a.mode = ?
        )
        ORDER BY p.id
        """,
        (mode,),
    ).fetchall()


def store_anchor(
    con: sqlite3.Connection,
    *,
    mode: str,
    merkle_root: str,
    record_ids: list[int],
    txid: str,
    raw_tx: str,
    broadcast_response: Optional[str] = None,
) -> int:
    cur = con.execute(
        """
        INSERT INTO provenance_anchors(mode, merkle_root, leaf_count, txid, raw_tx, broadcast_response, created_at_ms)
        VALUES (?,?,?,?,?,?,?)
        """,
        (mode, merkle_root, len(record_ids), txid, raw_tx, broadcast_response, _now_ms()),
    )
    anchor_id = int(cur.lastrowid)
    con.executemany(
        "INSERT INTO provenance_anchor_leaves(anchor_id, leaf_index, record_id) VALUES (?,?,?)",
        [(anchor_id, i, rid) for i, rid in enumerate(record_ids)],
    )
    return anchor_id


def build_bundle(con: sqlite3.Connection, event_id: int) -> dict[str, Any]:
    """Self-contained proof bundle a third party can check with `verify`."""
    prov = con.execute(
        "SELECT id, record_json, record_hash, signature FROM provenance_records WHERE event_id = ?",
        (int(event_id),),
    ).fetchone()
    if prov is None:
        raise LookupError(f"memory {event_id} has no provenance record")
    row = load_event(con, event_id)
    if row is None:
        raise LookupError(f"no events row with id {event_id}")
    bundle: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA,
        "content": event_content(row),
        "record": json.loads(prov["record_json"]),
        "record_hash": prov["record_hash"],
        "signature": prov["signature"],
        "anchor": None,
    }
    # Prefer a real (broadcast) anchor, newest first; fall back to a dry-run one.
    anchor = con.execute(
        """
        SELECT a.* FROM provenance_anchor_leaves l JOIN provenance_anchors a ON a.id = l.anchor_id
        WHERE l.record_id = ?
        ORDER BY (a.mode = 'broadcast') DESC, a.id DESC LIMIT 1
        """,
        (int(prov["id"]),),
    ).fetchone()
    if anchor is not None:
        leaves = con.execute(
            """
            SELECT p.record_hash FROM provenance_anchor_leaves l JOIN provenance_records p ON p.id = l.record_id
            WHERE l.anchor_id = ? ORDER BY l.leaf_index
            """,
            (int(anchor["id"]),),
        ).fetchall()
        hashes = [r["record_hash"] for r in leaves]
        root, proofs = merkle_root_and_proofs(hashes)
        if root != anchor["merkle_root"]:
            raise RuntimeError(f"stored anchor {anchor['id']} root does not match its leaves")
        index = hashes.index(prov["record_hash"])
        bundle["anchor"] = {
            "mode": anchor["mode"],
            "merkle_root": anchor["merkle_root"],
            "leaf_index": index,
            "leaf_count": len(hashes),
            "inclusion_proof": proofs[index],
            "txid": anchor["txid"],
            "raw_tx": anchor["raw_tx"],
        }
    return bundle
