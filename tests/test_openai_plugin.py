from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import ipaddress
import json
import sqlite3
import ssl
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import closing, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import memdb
from memdb_openai import anchor, cli, provenance
from memdb_openai.channel import OPENAI_CONNECTOR_SAN, OpenAITrust
from memdb_openai.server import AuthConfig, McpApp, RequestContext, make_http_server
from memdb_openai.verify import verify_bundle


# ---------------------------------------------------------------------------
# Test PKI standing in for OpenAI's connector CA (never the real one)
# ---------------------------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(
    *,
    subject: str,
    key,
    issuer_name: x509.Name,
    issuer_key,
    ca: bool,
    path_len: Optional[int] = None,
    san_dns: Optional[list[str]] = None,
    san_ip: Optional[list[str]] = None,
    eku=None,
) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
        )
    names: list[x509.GeneralName] = [x509.DNSName(n) for n in (san_dns or [])]
    names += [x509.IPAddress(ipaddress.ip_address(i)) for i in (san_ip or [])]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


class TestPKI:
    def __init__(self, label: str):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert(subject=f"{label} Root", key=self.root_key, issuer_name=_name(f"{label} Root"),
                          issuer_key=self.root_key, ca=True, path_len=1)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = _cert(subject=f"{label} Connectors mTLS intermediate CA", key=self.int_key,
                                  issuer_name=self.root.subject, issuer_key=self.root_key, ca=True, path_len=0)

    def leaf(self, *, san: str = OPENAI_CONNECTOR_SAN, eku=(ExtendedKeyUsageOID.CLIENT_AUTH,)):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _cert(subject=san, key=key, issuer_name=self.intermediate.subject, issuer_key=self.int_key,
                     ca=False, san_dns=[san], eku=list(eku))
        return cert, key

    def server_leaf(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _cert(subject="localhost", key=key, issuer_name=self.intermediate.subject, issuer_key=self.int_key,
                     ca=False, san_dns=["localhost"], san_ip=["127.0.0.1"], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        return cert, key

    def bundle_pem(self) -> bytes:
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (self.root, self.intermediate))

    def trust(self) -> OpenAITrust:
        return OpenAITrust.from_pem_bundle(self.bundle_pem())


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


# ---------------------------------------------------------------------------

class PluginTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.db_path = str(self.root / "memdb.sqlite3")
        self.attester = provenance.Attester.generate()
        self.app = McpApp(db_path=self.db_path, attester=self.attester)

    def con(self) -> sqlite3.Connection:
        con = memdb.connect(self.db_path)
        memdb.init_db(con)
        provenance.init_provenance(con)
        return con

    def call(self, name: str, arguments: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        resp = self.app.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}, ctx
        )
        assert resp is not None
        return resp["result"]

    def openai_ctx(self, pki: TestPKI) -> RequestContext:
        leaf, _ = pki.leaf()
        return RequestContext(channel=pki.trust().evaluate(leaf, transport="https-mtls"),
                              authorization={"method": "bearer", "subject": "owner"})

    def learn(self, ctx: RequestContext, title: str = "Anchor memdb provenance on BSV") -> dict[str, Any]:
        result = self.call("learn", {"type": "decision", "title": title, "tags": ["provenance"]}, ctx)
        self.assertFalse(result.get("isError"), result)
        return result["structuredContent"]

    def anchor_dry_run(self) -> dict[str, Any]:
        key_path = self.root / "attest.pem"
        if not key_path.exists():
            self.attester.write_pem(str(key_path))
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["--db", self.db_path, "--attest-key", str(key_path), "anchor"])
        self.assertEqual(code, 0)
        return json.loads(buf.getvalue())


class HashingAndSigningTests(PluginTestCase):
    def test_canonical_json_is_order_independent_and_hash_tracks_content(self) -> None:
        a = {"b": 1, "a": [1, {"y": "é", "x": None}]}
        b = {"a": [1, {"x": None, "y": "é"}], "b": 1}
        self.assertEqual(provenance.canonical_json(a), provenance.canonical_json(b))
        self.assertEqual(provenance.canonical_json(a), '{"a":[1,{"x":null,"y":"é"}],"b":1}'.encode())
        content = {"schema": "memdb.content.v1", "table": "events", "id": 1, "text": "x"}
        changed = dict(content, text="y")
        self.assertNotEqual(provenance.content_hash(content), provenance.content_hash(changed))

    def test_signature_verifies_only_for_the_signed_record_and_key(self) -> None:
        record = {"schema": provenance.RECORD_SCHEMA, "source": "unverified"}
        sig = self.attester.sign(record)
        self.assertTrue(provenance.verify_signature(record, sig, self.attester.public_key_hex))
        self.assertFalse(provenance.verify_signature(dict(record, source="openai"), sig, self.attester.public_key_hex))
        other = provenance.Attester.generate()
        self.assertFalse(provenance.verify_signature(record, sig, other.public_key_hex))
        self.assertFalse(provenance.verify_signature(record, "not base64!", self.attester.public_key_hex))

    def test_attestation_key_file_round_trips_and_is_private(self) -> None:
        path = self.root / "k.pem"
        self.attester.write_pem(str(path))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(provenance.Attester.from_file(str(path)).public_key_hex, self.attester.public_key_hex)
        with self.assertRaises(FileExistsError):
            self.attester.write_pem(str(path))


class MerkleTests(unittest.TestCase):
    def test_every_leaf_proves_into_the_root_for_many_tree_sizes(self) -> None:
        for n in range(1, 18):
            hashes = [hashlib.sha256(f"r{i}".encode()).hexdigest() for i in range(n)]
            root, proofs = provenance.merkle_root_and_proofs(hashes)
            for h, proof in zip(hashes, proofs):
                self.assertEqual(provenance.merkle_root_from_proof(h, proof), root, f"n={n}")

    def test_proof_rejects_foreign_leaf_and_tampered_sibling(self) -> None:
        hashes = [hashlib.sha256(f"r{i}".encode()).hexdigest() for i in range(5)]
        root, proofs = provenance.merkle_root_and_proofs(hashes)
        stranger = hashlib.sha256(b"stranger").hexdigest()
        self.assertNotEqual(provenance.merkle_root_from_proof(stranger, proofs[0]), root)
        bad = copy.deepcopy(proofs[2])
        bad[0]["hash"] = "00" * 32
        self.assertNotEqual(provenance.merkle_root_from_proof(hashes[2], bad), root)

    def test_leaf_and_node_hashes_are_domain_separated(self) -> None:
        h = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()]
        root, _ = provenance.merkle_root_and_proofs(h)
        # A single-leaf tree over the root's preimage must not collide with the 2-leaf root.
        self.assertNotEqual(provenance.merkle_root_and_proofs([root])[0], root)


class AnchorTxTests(unittest.TestCase):
    def test_ripemd160_fallback_matches_known_vectors(self) -> None:
        self.assertEqual(anchor._ripemd160(b"").hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")
        self.assertEqual(anchor._ripemd160(b"abc").hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        msg = b"a" * 200
        self.assertEqual(anchor._ripemd160(msg), hashlib.new("ripemd160", msg).digest())

    def test_dry_run_tx_commits_root_and_attester_and_is_validly_signed(self) -> None:
        root = hashlib.sha256(b"root").hexdigest()
        attester = provenance.Attester.generate().public_key_hex
        txid, raw = anchor.build_dry_run_anchor_tx(merkle_root=root, attester_public_key=attester)
        self.assertEqual(anchor.txid_of(bytes.fromhex(raw)), txid)
        self.assertEqual(anchor.find_anchor(raw), {"merkle_root": root, "attester_public_key": attester})
        outputs = anchor.parse_output_scripts(raw)
        self.assertEqual(outputs[0][0], 0)
        self.assertLess(outputs[1][0], anchor.DRY_RUN_INPUT_SATS)  # fee was paid
        self.assertEqual(bytes.fromhex(raw)[5:37][::-1].hex(), anchor.DRY_RUN_OUTPOINT_TXID)  # synthetic input

    def test_real_mode_signature_verifies_against_bip143_forkid_sighash(self) -> None:
        key = ec.generate_private_key(ec.SECP256K1())
        utxo = anchor.Utxo(txid="11" * 32, vout=1, satoshis=5000)
        root = hashlib.sha256(b"root").hexdigest()
        attester = "22" * 32
        _txid, raw = anchor.build_anchor_tx(merkle_root=root, attester_public_key=attester, funding_key=key, utxo=utxo)
        data = bytes.fromhex(raw)
        script_sig_len = data[41]
        script_sig = data[42:42 + script_sig_len]
        sig_len = script_sig[0]
        sig_with_type = script_sig[1:1 + sig_len]
        pub = script_sig[2 + sig_len:]
        self.assertEqual(sig_with_type[-1], anchor.SIGHASH_ALL_FORKID)
        self.assertEqual(pub, anchor.compressed_pubkey(key))
        outputs = [anchor.TxOut(s, sc) for s, sc in anchor.parse_output_scripts(raw)]
        lock = anchor.p2pkh_script(anchor.hash160(pub))
        self.assertEqual(outputs[1].script, lock)  # change back to the funding key
        digest = anchor.sighash_forkid(utxo, lock, outputs)
        key.public_key().verify(sig_with_type[:-1], digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        _r, s = decode_dss_signature(sig_with_type[:-1])
        self.assertLessEqual(s, anchor.SECP256K1_N // 2)

    def test_wif_decoding_matches_known_key(self) -> None:
        # Well-known test vector (private key = 1), never funded with anything of value.
        key = anchor.private_key_from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        self.assertEqual(key.private_numbers().private_value, 1)
        with self.assertRaises(ValueError):
            anchor.private_key_from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm")


class ChannelTests(PluginTestCase):
    def test_openai_cert_from_pinned_ca_is_verified(self) -> None:
        pki = TestPKI("OpenAI-test")
        leaf, _ = pki.leaf()
        ev = pki.trust().evaluate(leaf, transport="https-mtls")
        self.assertTrue(ev["openai_verified"], ev)
        self.assertIn(OPENAI_CONNECTOR_SAN, ev["client_cert_san"])

    def test_lookalike_certs_are_not_openai(self) -> None:
        pki = TestPKI("OpenAI-test")
        trust = pki.trust()
        impostor_leaf, _ = TestPKI("Impostor").leaf()  # same SAN, different CA
        self.assertFalse(trust.evaluate(impostor_leaf, transport="https-mtls")["openai_verified"])
        wrong_san, _ = pki.leaf(san="evil.example.com")
        self.assertFalse(trust.evaluate(wrong_san, transport="https-mtls")["openai_verified"])
        server_only, _ = pki.leaf(eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
        self.assertFalse(trust.evaluate(server_only, transport="https-mtls")["openai_verified"])
        self.assertFalse(trust.evaluate(None, transport="https")["openai_verified"])


class EndToEndTests(PluginTestCase):
    def test_openai_write_is_attested_anchored_and_verifies(self) -> None:
        pki = TestPKI("OpenAI-test")
        written = self.learn(self.openai_ctx(pki))
        self.assertEqual(written["provenance"]["source"], "openai")
        anchored = self.anchor_dry_run()
        self.assertEqual(anchored["mode"], "dry-run")
        self.assertFalse(anchored["broadcast"])

        with closing(self.con()) as con:
            bundle = provenance.build_bundle(con, written["id"])
            result = verify_bundle(bundle, attester_public_key=self.attester.public_key_hex, con=con)
        self.assertTrue(result["ok"], result["checks"])
        self.assertEqual(result["source"], "openai")
        self.assertEqual(result["anchored"], "dry-run")
        self.assertEqual(bundle["anchor"]["txid"], anchored["txid"])

    def test_batch_anchor_gives_each_record_its_own_inclusion_proof(self) -> None:
        pki = TestPKI("OpenAI-test")
        ids = [self.learn(self.openai_ctx(pki), title=f"fact {i}")["id"] for i in range(5)]
        anchored = self.anchor_dry_run()
        self.assertEqual(anchored["anchored"], 5)
        self.assertEqual(self.anchor_dry_run()["anchored"], 0)  # nothing left pending
        with closing(self.con()) as con:
            for event_id in ids:
                bundle = provenance.build_bundle(con, event_id)
                self.assertEqual(bundle["anchor"]["merkle_root"], anchored["merkle_root"])
                self.assertTrue(verify_bundle(bundle, attester_public_key=self.attester.public_key_hex)["ok"])

    def test_tampered_content_fails(self) -> None:
        written = self.learn(self.openai_ctx(TestPKI("OpenAI-test")))
        self.anchor_dry_run()
        with closing(self.con()) as con:
            bundle = provenance.build_bundle(con, written["id"])
        bundle["content"]["text"] = "decision: Never anchor anything"
        result = verify_bundle(bundle, attester_public_key=self.attester.public_key_hex)
        self.assertFalse(result["ok"])
        self.assertIn("content_hash", [c["check"] for c in result["checks"] if not c["ok"]])

    def test_relabelled_source_fails(self) -> None:
        stdio_ctx = RequestContext(channel={"transport": "stdio", "openai_verified": False},
                                   authorization={"method": "local-process", "subject": None})
        written = self.learn(stdio_ctx)
        self.assertEqual(written["provenance"]["source"], "unverified")
        self.anchor_dry_run()
        with closing(self.con()) as con:
            bundle = provenance.build_bundle(con, written["id"])
        self.assertTrue(verify_bundle(bundle, attester_public_key=self.attester.public_key_hex)["ok"])

        relabelled = copy.deepcopy(bundle)
        relabelled["record"]["source"] = "openai"
        relabelled["record"]["channel"]["openai_verified"] = True
        result = verify_bundle(relabelled, attester_public_key=self.attester.public_key_hex)
        self.assertFalse(result["ok"])
        failed = {c["check"] for c in result["checks"] if not c["ok"]}
        self.assertTrue({"signature", "record_hash", "merkle_inclusion"} <= failed, failed)

    def test_resigned_by_another_key_fails_against_pinned_key(self) -> None:
        written = self.learn(self.openai_ctx(TestPKI("OpenAI-test")))
        with closing(self.con()) as con:
            bundle = provenance.build_bundle(con, written["id"])
        forger = provenance.Attester.generate()
        forged = copy.deepcopy(bundle)
        forged["record"]["attester"]["public_key"] = forger.public_key_hex
        forged["signature"] = forger.sign(forged["record"])
        forged["record_hash"] = provenance.record_hash(forged["record"])
        result = verify_bundle(forged, attester_public_key=self.attester.public_key_hex)
        self.assertFalse(result["ok"])
        # And it only "passes" if the verifier trusts the forger's key, which is why the key is pinned.
        self.assertTrue(verify_bundle(forged, attester_public_key=forger.public_key_hex)["ok"])

    def test_swapped_anchor_transaction_fails(self) -> None:
        written = self.learn(self.openai_ctx(TestPKI("OpenAI-test")))
        self.anchor_dry_run()
        with closing(self.con()) as con:
            bundle = provenance.build_bundle(con, written["id"])
        other_txid, other_raw = anchor.build_dry_run_anchor_tx(
            merkle_root="ab" * 32, attester_public_key=self.attester.public_key_hex)
        bundle["anchor"]["raw_tx"] = other_raw
        result = verify_bundle(bundle, attester_public_key=self.attester.public_key_hex)
        failed = {c["check"] for c in result["checks"] if not c["ok"]}
        self.assertIn("anchor_commits_root", failed)
        self.assertIn("anchor_txid", failed)

    def test_build_only_signs_a_real_mode_tx_but_stores_and_sends_nothing(self) -> None:
        self.learn(self.openai_ctx(TestPKI("OpenAI-test")))
        key_path = self.root / "attest.pem"
        self.attester.write_pem(str(key_path))
        wif = self.root / "funding.wif"
        wif.write_text("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn\n")  # private key 1, test vector
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["--db", self.db_path, "--attest-key", str(key_path), "anchor", "--build-only",
                             "--funding-key-file", str(wif), "--utxo", f"{'33' * 32}:0:2000"])
        self.assertEqual(code, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual((out["mode"], out["stored"], out["broadcast"]), ("build-only", False, False))
        self.assertEqual(anchor.find_anchor(out["raw_tx"])["merkle_root"], out["merkle_root"])
        with closing(self.con()) as con:
            self.assertEqual(con.execute("SELECT count(*) FROM provenance_anchors").fetchone()[0], 0)

    def test_store_is_append_only_and_attested_rows_cannot_be_rewritten(self) -> None:
        written = self.learn(self.openai_ctx(TestPKI("OpenAI-test")))
        self.anchor_dry_run()
        with closing(self.con()) as con:
            for sql in (
                "UPDATE provenance_records SET source = 'openai'",
                "DELETE FROM provenance_records",
                "UPDATE provenance_anchors SET merkle_root = 'x'",
                "DELETE FROM provenance_anchor_leaves",
                f"UPDATE events SET text = 'rewritten' WHERE id = {written['id']}",
                f"DELETE FROM events WHERE id = {written['id']}",
            ):
                with self.assertRaises(sqlite3.IntegrityError, msg=sql):
                    con.execute(sql)
            with self.assertRaises(sqlite3.IntegrityError):
                provenance.attest_event(con, event_id=written["id"],
                                        channel={"transport": "x", "openai_verified": True},
                                        authorization={}, attester=self.attester)
            # memdb's own migration still runs over attested rows.
            memdb.init_db(con)

    def test_live_row_check_catches_rewrite_that_bypassed_triggers(self) -> None:
        written = self.learn(self.openai_ctx(TestPKI("OpenAI-test")))
        with closing(self.con()) as con:
            bundle = provenance.build_bundle(con, written["id"])
            con.execute("DROP TRIGGER events_attested_no_content_update")
            con.execute("UPDATE events SET text = 'rewritten' WHERE id = ?", (written["id"],))
            con.commit()
            result = verify_bundle(bundle, attester_public_key=self.attester.public_key_hex, con=con)
        self.assertFalse(result["ok"])
        self.assertIn("live_row_matches", [c["check"] for c in result["checks"] if not c["ok"]])

    def test_search_and_recall_show_which_source_wrote_each_memory(self) -> None:
        pki = TestPKI("OpenAI-test")
        self.learn(self.openai_ctx(pki), title="Treechat posts go to BSV")
        with closing(self.con()) as con:  # a CLI write: no provenance record
            memdb.record_learned(con, memory_type="lesson", title="BSV fees are low")
        recall = self.call("recall", {"query": "BSV"}, self.openai_ctx(pki))["structuredContent"]["results"]
        by_text = {r["text"].splitlines()[0]: r["provenance"] for r in recall}
        self.assertEqual(by_text["decision: Treechat posts go to BSV"]["source"], "openai")
        self.assertIsNone(by_text["lesson: BSV fees are low"])
        search = self.call("search", {"query": "Treechat"}, self.openai_ctx(pki))["structuredContent"]["results"]
        self.assertEqual(search[0]["provenance"]["source"], "openai")


class HttpTransportTests(PluginTestCase):
    """Real HTTPS + mTLS on loopback: the source comes from the TLS handshake, not the request body."""

    def setUp(self) -> None:
        super().setUp()
        self.pki = TestPKI("OpenAI-test")
        server_cert, server_key = self.pki.server_leaf()
        (self.root / "server.pem").write_bytes(_pem(server_cert) + _pem(self.pki.intermediate))
        (self.root / "server.key").write_bytes(_key_pem(server_key))
        auth = AuthConfig(bearer_sha256={hashlib.sha256(b"s3cret").hexdigest(): "owner"})
        self.httpd = make_http_server(self.app, host="127.0.0.1", port=0, auth=auth, trust=self.pki.trust(),
                                      tls_cert=str(self.root / "server.pem"), tls_key=str(self.root / "server.key"))
        self.port = self.httpd.server_address[1]
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def post(self, body: dict[str, Any], *, client=None, token: Optional[str] = "s3cret") -> tuple[int, Any]:
        ctx = ssl.create_default_context(cadata=_pem(self.pki.root).decode())
        if client is not None:
            cert, key = client
            (self.root / "client.pem").write_bytes(_pem(cert) + _pem(self.pki.intermediate))
            (self.root / "client.key").write_bytes(_key_pem(key))
            ctx.load_cert_chain(str(self.root / "client.pem"), str(self.root / "client.key"))
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"https://127.0.0.1:{self.port}/mcp", data=json.dumps(body).encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            return exc.code, None

    def learn_body(self) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": "learn", "arguments": {"type": "lesson", "title": "via https"}}}

    def test_mtls_client_cert_makes_source_openai(self) -> None:
        status, body = self.post(self.learn_body(), client=self.pki.leaf())
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["structuredContent"]["provenance"]["source"], "openai")

    def test_no_client_cert_is_unverified_and_no_token_is_rejected(self) -> None:
        status, body = self.post(self.learn_body())
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["structuredContent"]["provenance"]["source"], "unverified")
        self.assertEqual(self.post(self.learn_body(), token=None)[0], 401)
        self.assertEqual(self.post(self.learn_body(), token="wrong")[0], 401)

    def test_notification_gets_202(self) -> None:
        status, body = self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertEqual((status, body), (202, None))


if __name__ == "__main__":
    unittest.main()
