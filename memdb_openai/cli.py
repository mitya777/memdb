"""memdb-openai CLI: keygen, serve, anchor, proof, verify."""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import closing
from typing import Any, Optional

import memdb

from . import anchor as anchor_mod
from . import provenance
from .channel import OpenAITrust
from .server import AuthConfig, McpApp, make_http_server, serve_stdio
from .verify import verify_bundle


def _db(args: argparse.Namespace):
    con = memdb.connect(args.db)
    memdb.init_db(con)
    provenance.init_provenance(con)
    return con


def _attester(args: argparse.Namespace) -> provenance.Attester:
    path = args.attest_key or os.environ.get("MEMDB_ATTEST_KEY_FILE")
    if not path:
        raise SystemExit("attestation key required: --attest-key or MEMDB_ATTEST_KEY_FILE (create one with `keygen`)")
    return provenance.Attester.from_file(path)


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def cmd_keygen(args: argparse.Namespace) -> int:
    attester = provenance.Attester.generate()
    attester.write_pem(args.out)
    _print({"private_key_file": os.path.abspath(args.out), "public_key": attester.public_key_hex})
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    app = McpApp(db_path=args.db, attester=_attester(args))
    if args.stdio:
        serve_stdio(app)
        return 0
    trust = OpenAITrust.from_file(args.openai_ca) if args.openai_ca else None
    if args.insecure_no_auth:
        auth = AuthConfig(allow_anonymous=True)
    elif args.auth_config:
        auth = AuthConfig.from_file(args.auth_config)
    else:
        raise SystemExit("--auth-config is required for HTTP (or --insecure-no-auth for local testing)")
    host, _, port = args.http.rpartition(":")
    httpd = make_http_server(
        app,
        host=host or "127.0.0.1",
        port=int(port),
        auth=auth,
        trust=trust,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        client_cert_header=args.client_cert_header,
    )
    print(f"memdb-openai MCP listening on {args.http} (openai mTLS check: {'on' if trust else 'off'})", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_anchor(args: argparse.Namespace) -> int:
    attester = _attester(args)
    if args.build_only and args.broadcast:
        raise SystemExit("--build-only and --broadcast are exclusive")
    mode = "broadcast" if (args.broadcast or args.build_only) else "dry-run"
    with closing(_db(args)) as con:
        pending = provenance.unanchored_records(con, mode)
        if args.limit:
            pending = pending[: args.limit]
        if not pending:
            _print({"mode": mode, "anchored": 0, "message": "nothing to anchor"})
            return 0
        hashes = [r["record_hash"] for r in pending]
        root, _ = provenance.merkle_root_and_proofs(hashes)

        response: Optional[str] = None
        if mode == "dry-run":
            txid, raw_tx = anchor_mod.build_dry_run_anchor_tx(merkle_root=root, attester_public_key=attester.public_key_hex)
        else:
            missing = [
                name
                for name, value in (
                    ("--funding-key-file", args.funding_key_file),
                    ("--utxo", args.utxo),
                    ("--broadcast-url", args.broadcast_url),
                )
                if not value
            ]
            if args.build_only:
                missing = [m for m in missing if m != "--broadcast-url"]
            if missing:
                raise SystemExit(f"--broadcast needs {', '.join(missing)}")
            with open(args.funding_key_file, "r", encoding="ascii") as fh:
                funding_key = anchor_mod.private_key_from_wif(fh.read())
            txid, raw_tx = anchor_mod.build_anchor_tx(
                merkle_root=root,
                attester_public_key=attester.public_key_hex,
                funding_key=funding_key,
                utxo=anchor_mod.Utxo.parse(args.utxo),
                fee_rate_sat_per_kb=args.fee_rate,
            )
            if args.build_only:
                _print({"mode": "build-only", "records": len(hashes), "merkle_root": root, "txid": txid,
                        "raw_tx": raw_tx, "stored": False, "broadcast": False})
                return 0
            response = anchor_mod.broadcast_arc(raw_tx, args.broadcast_url, os.environ.get("MEMDB_ANCHOR_ARC_TOKEN"))

        anchor_id = provenance.store_anchor(
            con,
            mode=mode,
            merkle_root=root,
            record_ids=[int(r["id"]) for r in pending],
            txid=txid,
            raw_tx=raw_tx,
            broadcast_response=response,
        )
        con.commit()
    _print({"mode": mode, "anchor_id": anchor_id, "anchored": len(hashes), "merkle_root": root, "txid": txid,
            "broadcast": mode == "broadcast", "raw_tx": raw_tx})
    return 0


def cmd_proof(args: argparse.Namespace) -> int:
    with closing(_db(args)) as con:
        try:
            bundle = provenance.build_bundle(con, args.memory_id)
        except LookupError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.bundle, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    con = None
    if args.check_db:
        con = memdb.connect(args.db)
    try:
        result = verify_bundle(
            bundle,
            attester_public_key=args.attester_key,
            fetch_tx=anchor_mod.fetch_tx_hex if args.fetch_tx else None,
            con=con,
        )
    finally:
        if con is not None:
            con.close()
    _print(result)
    return 0 if result["ok"] else 1


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="memdb-openai", description="memdb MCP plugin for OpenAI with signed, BSV-anchored provenance")
    p.add_argument("--db", default=os.environ.get("MEMDB_PATH", "/root/clawd/memory/memdb.sqlite3"))
    p.add_argument("--attest-key", default=None, help="Ed25519 PEM (default: $MEMDB_ATTEST_KEY_FILE)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("keygen", help="Create a new Ed25519 attestation key (file mode 0600, refuses to overwrite)")
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("serve", help="Run the MCP server")
    mode = sp.add_mutually_exclusive_group(required=True)
    mode.add_argument("--stdio", action="store_true", help="stdio transport (local Codex); writes are source 'unverified'")
    mode.add_argument("--http", metavar="HOST:PORT", help="Streamable HTTP transport on POST /mcp")
    sp.add_argument("--auth-config", default=os.environ.get("MEMDB_OPENAI_AUTH_CONFIG"))
    sp.add_argument("--insecure-no-auth", action="store_true", help="Accept unauthenticated requests (tests only)")
    sp.add_argument("--openai-ca", default=os.environ.get("MEMDB_OPENAI_MTLS_CA"), help="PEM bundle: OpenAI root + Connectors mTLS intermediate")
    sp.add_argument("--tls-cert", default=None)
    sp.add_argument("--tls-key", default=None)
    sp.add_argument("--client-cert-header", default=None, help="Header carrying the proxy-verified client cert (loopback bind only)")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("anchor", help="Commit pending provenance records under one Merkle root in a BSV tx (dry run by default)")
    sp.add_argument("--broadcast", action="store_true", help="Really broadcast to mainnet. Spends funds.")
    sp.add_argument("--build-only", action="store_true", help="Build and sign the real tx from --funding-key-file/--utxo, print it, store and send nothing")
    sp.add_argument("--funding-key-file", default=None, help="File holding a WIF private key that controls --utxo")
    sp.add_argument("--utxo", default=None, help="txid:vout:satoshis of a P2PKH output of the funding key")
    sp.add_argument("--broadcast-url", default=os.environ.get("MEMDB_ANCHOR_BROADCAST_URL"), help="ARC base URL")
    sp.add_argument("--fee-rate", type=int, default=anchor_mod.DEFAULT_FEE_RATE_SAT_PER_KB, help="sat/kB")
    sp.add_argument("--limit", type=int, default=None)
    sp.set_defaults(func=cmd_anchor)

    sp = sub.add_parser("proof", help="Export a memory's proof bundle")
    sp.add_argument("memory_id", type=int)
    sp.add_argument("--out", default=None)
    sp.set_defaults(func=cmd_proof)

    sp = sub.add_parser("verify", help="Verify a proof bundle (content hash, signature, Merkle proof, anchor tx)")
    sp.add_argument("bundle")
    sp.add_argument("--attester-key", required=True, help="Hex Ed25519 public key you trust for this memdb")
    sp.add_argument("--fetch-tx", action="store_true", help="Compare against the network copy of the anchor tx (WhatsOnChain)")
    sp.add_argument("--check-db", action="store_true", help="Also check the live memdb row at --db")
    sp.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
