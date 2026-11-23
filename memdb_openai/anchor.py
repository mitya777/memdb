"""Bitcoin SV anchoring: commit a Merkle root of provenance records in an OP_RETURN output.

The anchor output script is:

    OP_FALSE OP_RETURN <"memdb.anchor.v1"> <merkle_root: 32 bytes> <attester_pubkey: 32 bytes>

The transaction spends one P2PKH UTXO and returns the change to the same key.

Default mode is a dry run: the transaction is built and signed with a throwaway key
over a synthetic outpoint, so it is structurally real but can never be accepted by
the network and spends nothing. Broadcasting needs an explicit `broadcast=True`, a
funding key file, a real UTXO, and a broadcaster URL supplied by the operator.
"""

from __future__ import annotations

import hashlib
import json
import math
import urllib.request
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

ANCHOR_PREFIX = b"memdb.anchor.v1"
SIGHASH_ALL_FORKID = 0x41
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DEFAULT_FEE_RATE_SAT_PER_KB = 100
DUST_LIMIT = 1

DRY_RUN_OUTPOINT_TXID = hashlib.sha256(b"memdb dry-run anchor: not a real outpoint").hexdigest()
DRY_RUN_INPUT_SATS = 10_000


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except ValueError:  # OpenSSL builds without legacy digests
        return _ripemd160(sha)


def _ripemd160(msg: bytes) -> bytes:
    # Compact pure-Python RIPEMD-160, used only when hashlib lacks it.
    def rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    f = [
        lambda x, y, z: x ^ y ^ z,
        lambda x, y, z: (x & y) | (~x & z),
        lambda x, y, z: (x | ~y) ^ z,
        lambda x, y, z: (x & z) | (y & ~z),
        lambda x, y, z: x ^ (y | ~z),
    ]
    kl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    rl = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]
    rr = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]
    sl = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]
    sr = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + (8 * len(msg)).to_bytes(8, "little")
    for block in range(0, len(padded), 64):
        x = [int.from_bytes(padded[block + 4 * i: block + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j // 16
            t = (rol((al + (f[r](bl, cl, dl) & 0xFFFFFFFF) + x[rl[j]] + kl[r]) & 0xFFFFFFFF, sl[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + (f[4 - r](br, cr, dr) & 0xFFFFFFFF) + x[rr[j]] + kr[r]) & 0xFFFFFFFF, sr[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return b"".join(v.to_bytes(4, "little") for v in h)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def push_data(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xFFFF:
        return b"\x4d" + n.to_bytes(2, "little") + data
    return b"\x4e" + n.to_bytes(4, "little") + data


def p2pkh_script(pubkey_hash: bytes) -> bytes:
    return b"\x76\xa9" + push_data(pubkey_hash) + b"\x88\xac"


def anchor_script(merkle_root_hex: str, attester_public_key_hex: str) -> bytes:
    root = bytes.fromhex(merkle_root_hex)
    attester = bytes.fromhex(attester_public_key_hex)
    if len(root) != 32 or len(attester) != 32:
        raise ValueError("merkle root and attester key must be 32 bytes each")
    return b"\x00\x6a" + push_data(ANCHOR_PREFIX) + push_data(root) + push_data(attester)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode_check(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        raise ValueError("bad base58check checksum")
    return payload


def private_key_from_wif(wif: str) -> ec.EllipticCurvePrivateKey:
    payload = _b58decode_check(wif.strip())
    if payload[0] != 0x80:
        raise ValueError("WIF is not a mainnet private key")
    secret = payload[1:33]
    if len(payload) not in (33, 34):
        raise ValueError("unexpected WIF length")
    return ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP256K1())


def compressed_pubkey(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


# ---------------------------------------------------------------------------
# Transaction model, sighash, signing
# ---------------------------------------------------------------------------

@dataclass
class Utxo:
    txid: str  # big-endian hex as shown by explorers
    vout: int
    satoshis: int

    @classmethod
    def parse(cls, spec: str) -> "Utxo":
        txid, vout, sats = spec.split(":")
        if len(bytes.fromhex(txid)) != 32:
            raise ValueError("utxo txid must be 32 bytes hex")
        return cls(txid=txid, vout=int(vout), satoshis=int(sats))


@dataclass
class TxOut:
    satoshis: int
    script: bytes

    def serialize(self) -> bytes:
        return self.satoshis.to_bytes(8, "little") + varint(len(self.script)) + self.script


def _outpoint(utxo: Utxo) -> bytes:
    return bytes.fromhex(utxo.txid)[::-1] + utxo.vout.to_bytes(4, "little")


def sighash_forkid(utxo: Utxo, script_code: bytes, outputs: list[TxOut], *, version: int = 1, locktime: int = 0) -> bytes:
    """BIP143-style digest with SIGHASH_ALL|FORKID, single input."""
    sequence = (0xFFFFFFFF).to_bytes(4, "little")
    preimage = (
        version.to_bytes(4, "little")
        + sha256d(_outpoint(utxo))
        + sha256d(sequence)
        + _outpoint(utxo)
        + varint(len(script_code)) + script_code
        + utxo.satoshis.to_bytes(8, "little")
        + sequence
        + sha256d(b"".join(o.serialize() for o in outputs))
        + locktime.to_bytes(4, "little")
        + SIGHASH_ALL_FORKID.to_bytes(4, "little")
    )
    return sha256d(preimage)


def _sign_low_s(key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
    der = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return encode_dss_signature(r, s)


def serialize_tx(utxo: Utxo, script_sig: bytes, outputs: list[TxOut], *, version: int = 1, locktime: int = 0) -> bytes:
    return (
        version.to_bytes(4, "little")
        + varint(1)
        + _outpoint(utxo)
        + varint(len(script_sig)) + script_sig
        + (0xFFFFFFFF).to_bytes(4, "little")
        + varint(len(outputs))
        + b"".join(o.serialize() for o in outputs)
        + locktime.to_bytes(4, "little")
    )


def txid_of(raw_tx: bytes) -> str:
    return sha256d(raw_tx)[::-1].hex()


def build_anchor_tx(
    *,
    merkle_root: str,
    attester_public_key: str,
    funding_key: ec.EllipticCurvePrivateKey,
    utxo: Utxo,
    fee_rate_sat_per_kb: int = DEFAULT_FEE_RATE_SAT_PER_KB,
) -> tuple[str, str]:
    """Return (txid, raw_tx_hex) for a signed anchor transaction."""
    pub = compressed_pubkey(funding_key)
    lock = p2pkh_script(hash160(pub))
    op_return = TxOut(0, anchor_script(merkle_root, attester_public_key))

    def assemble(fee: int) -> bytes:
        change = utxo.satoshis - fee
        if change < DUST_LIMIT:
            raise ValueError(f"UTXO of {utxo.satoshis} sats cannot cover fee {fee}")
        outputs = [op_return, TxOut(change, lock)]
        digest = sighash_forkid(utxo, lock, outputs)
        sig = _sign_low_s(funding_key, digest) + bytes([SIGHASH_ALL_FORKID])
        return serialize_tx(utxo, push_data(sig) + push_data(pub), outputs)

    raw = assemble(1)
    fee = max(1, math.ceil(len(raw) * fee_rate_sat_per_kb / 1000))
    raw = assemble(fee)
    return txid_of(raw), raw.hex()


def build_dry_run_anchor_tx(*, merkle_root: str, attester_public_key: str) -> tuple[str, str]:
    """Signed with a throwaway key over a synthetic outpoint. Never valid on the network."""
    throwaway = ec.generate_private_key(ec.SECP256K1())
    utxo = Utxo(txid=DRY_RUN_OUTPOINT_TXID, vout=0, satoshis=DRY_RUN_INPUT_SATS)
    return build_anchor_tx(
        merkle_root=merkle_root,
        attester_public_key=attester_public_key,
        funding_key=throwaway,
        utxo=utxo,
    )


# ---------------------------------------------------------------------------
# Parsing (for verification)
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated transaction")
        out = self.data[self.pos: self.pos + n]
        self.pos += n
        return out

    def varint(self) -> int:
        first = self.take(1)[0]
        if first < 0xFD:
            return first
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        return int.from_bytes(self.take(size), "little")


def parse_output_scripts(raw_tx_hex: str) -> list[tuple[int, bytes]]:
    r = _Reader(bytes.fromhex(raw_tx_hex))
    r.take(4)
    for _ in range(r.varint()):
        r.take(36)
        r.take(r.varint())
        r.take(4)
    outputs = []
    for _ in range(r.varint()):
        sats = int.from_bytes(r.take(8), "little")
        outputs.append((sats, r.take(r.varint())))
    r.take(4)
    if r.pos != len(r.data):
        raise ValueError("trailing bytes after transaction")
    return outputs


def _parse_pushes(script: bytes) -> list[bytes]:
    pushes, i = [], 0
    while i < len(script):
        op = script[i]
        i += 1
        if 0 < op < 0x4C:
            n = op
        elif op == 0x4C:
            n, i = script[i], i + 1
        elif op == 0x4D:
            n, i = int.from_bytes(script[i:i + 2], "little"), i + 2
        elif op == 0x4E:
            n, i = int.from_bytes(script[i:i + 4], "little"), i + 4
        else:
            raise ValueError(f"unexpected opcode 0x{op:02x} in anchor data")
        pushes.append(script[i:i + n])
        i += n
    return pushes


def find_anchor(raw_tx_hex: str) -> Optional[dict[str, str]]:
    """Return {merkle_root, attester_public_key} from the tx's anchor output, if any."""
    for _sats, script in parse_output_scripts(raw_tx_hex):
        if not script.startswith(b"\x00\x6a"):
            continue
        try:
            pushes = _parse_pushes(script[2:])
        except (ValueError, IndexError):
            continue
        if len(pushes) == 3 and pushes[0] == ANCHOR_PREFIX and len(pushes[1]) == 32 and len(pushes[2]) == 32:
            return {"merkle_root": pushes[1].hex(), "attester_public_key": pushes[2].hex()}
    return None


# ---------------------------------------------------------------------------
# Network (only used when the operator explicitly asks for it)
# ---------------------------------------------------------------------------

def broadcast_arc(raw_tx_hex: str, url: str, token: Optional[str] = None, timeout: float = 30.0) -> str:
    """POST a raw tx to an ARC endpoint (e.g. https://arc.taal.com). Returns the response body."""
    req = urllib.request.Request(
        url.rstrip("/") + "/v1/tx",
        data=json.dumps({"rawTx": raw_tx_hex}).encode("utf-8"),
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def fetch_tx_hex(txid: str, base_url: str = "https://api.whatsonchain.com/v1/bsv/main", timeout: float = 30.0) -> str:
    with urllib.request.urlopen(f"{base_url}/tx/{txid}/hex", timeout=timeout) as resp:
        return resp.read().decode("ascii").strip()
