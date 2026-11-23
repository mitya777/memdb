"""Third-party verification of a memdb proof bundle.

Checks, in order:
  1. content    the memory's canonical content hashes to record.content_sha256
  2. signature  the record is signed by the pinned memdb attestation key
  3. merkle     the record hash is included under the anchored Merkle root
  4. anchor tx  the transaction's OP_RETURN commits that root and attester key, and
                its txid matches the raw bytes
  5. onchain    (optional, needs network) the network's copy of the tx is identical
  6. live row   (optional, needs the db) the row in memdb still matches the bundle

The bundle needs nothing from memdb to check 1-4: a verifier only needs the
attestation public key, which the operator publishes out of band.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Callable, Optional

from . import anchor as anchor_mod
from . import provenance

PROVES = [
    "the memory's content is byte-for-byte what memdb attested (any edit breaks the content hash)",
    "the source label, channel evidence and receive time were signed by the memdb attestation key and not changed since",
    "when anchored on chain: the record existed no later than the block containing the anchor transaction",
    "source 'openai' means: memdb's server saw a TLS client certificate chaining to OpenAI's connector CA with SAN mtls.prod.connectors.openai.com on the request that wrote it",
]
DOES_NOT_PROVE = [
    "which model, if any, generated the text (OpenAI does not sign model outputs or tool-call arguments)",
    "anything independently of the memdb operator: the channel check is memdb's signed statement, a third party cannot replay the TLS handshake",
    "that memdb recorded every write; only that the attested ones are unaltered",
    "for a dry-run anchor: any timestamp at all (the transaction was never broadcast)",
]


def verify_bundle(
    bundle: dict[str, Any],
    *,
    attester_public_key: str,
    fetch_tx: Optional[Callable[[str], str]] = None,
    con: Optional[sqlite3.Connection] = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append({"check": name, "ok": bool(ok), **({"detail": detail} if detail else {})})
        return ok

    record = bundle.get("record") or {}
    content = bundle.get("content") or {}

    # 1. content
    actual_content_hash = provenance.content_hash(content)
    check(
        "content_hash",
        actual_content_hash == record.get("content_sha256"),
        f"content sha256 {actual_content_hash} vs record {record.get('content_sha256')}",
    )
    check(
        "content_identity",
        record.get("memory") == {"table": content.get("table"), "id": content.get("id")},
        "record.memory must name the same row as the content",
    )

    # 2. signature over the record, by the pinned key
    rhash = provenance.record_hash(record)
    check("record_hash", rhash == bundle.get("record_hash"), f"recomputed {rhash}")
    key_in_record = (record.get("attester") or {}).get("public_key")
    check(
        "attester_pinned",
        key_in_record == attester_public_key.lower(),
        "record must be signed by the attestation key you trust, not just any key",
    )
    check(
        "signature",
        provenance.verify_signature(record, bundle.get("signature") or "", attester_public_key),
        "Ed25519 over canonical record JSON",
    )
    channel = record.get("channel") or {}
    source = record.get("source")
    check(
        "source_consistent",
        (source == provenance.SOURCE_OPENAI) == (channel.get("openai_verified") is True),
        "source 'openai' only with verified OpenAI channel evidence",
    )

    # 3-5. anchor
    anchor_info = bundle.get("anchor")
    anchored = "none"
    if anchor_info:
        root = provenance.merkle_root_from_proof(rhash, anchor_info.get("inclusion_proof") or [])
        check("merkle_inclusion", root == anchor_info.get("merkle_root"), f"computed root {root}")
        raw_tx = anchor_info.get("raw_tx") or ""
        try:
            txid = anchor_mod.txid_of(bytes.fromhex(raw_tx))
            committed = anchor_mod.find_anchor(raw_tx)
        except ValueError as exc:
            txid, committed = None, None
            check("anchor_tx_parse", False, str(exc))
        check("anchor_txid", txid == anchor_info.get("txid"), f"sha256d(raw_tx) = {txid}")
        check(
            "anchor_commits_root",
            committed is not None and committed["merkle_root"] == anchor_info.get("merkle_root") == root,
            "OP_RETURN memdb.anchor.v1 <root> must equal the proven root",
        )
        check(
            "anchor_commits_attester",
            committed is not None and committed["attester_public_key"] == attester_public_key.lower(),
            "OP_RETURN must name the same attestation key",
        )
        mode = anchor_info.get("mode")
        if mode == "broadcast":
            anchored = "onchain-unchecked"
            if fetch_tx is not None:
                try:
                    network_raw = fetch_tx(anchor_info["txid"]).lower()
                except Exception as exc:  # network failures are a failed check, not a crash
                    check("onchain_tx", False, f"fetch failed: {exc}")
                else:
                    if check("onchain_tx", network_raw == raw_tx.lower(), "network copy matches bundle"):
                        anchored = "onchain"
        else:
            anchored = "dry-run"

    # 6. live row
    if con is not None:
        row = provenance.load_event(con, int(content.get("id", -1)))
        live_ok = row is not None and provenance.content_hash(provenance.event_content(row)) == record.get("content_sha256")
        check("live_row_matches", live_ok, "current memdb row still hashes to the attested content")
        stored = con.execute(
            "SELECT record_hash FROM provenance_records WHERE event_id = ?", (int(content.get("id", -1)),)
        ).fetchone()
        check("live_record_matches", stored is not None and stored["record_hash"] == rhash, "stored record hash matches")

    ok = all(c["ok"] for c in checks)
    return {
        "ok": ok,
        "memory_id": content.get("id"),
        "source": source if ok else None,
        "claimed_source": source,
        "received_at": record.get("received_at"),
        "anchored": anchored,
        "txid": (anchor_info or {}).get("txid"),
        "checks": checks,
        "proves": PROVES if ok else [],
        "does_not_prove": DOES_NOT_PROVE,
    }
