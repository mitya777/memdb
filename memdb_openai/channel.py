"""Channel evidence: how the server decides a write came through OpenAI.

The only OpenAI-provided origin signal documented today is the OpenAI-managed TLS
client certificate ChatGPT presents to MCP servers
(https://developers.openai.com/plugins/build/auth, "Client identification"):

  - the leaf chains to the "OpenAI Connectors mTLS intermediate CA",
  - it is valid for client authentication,
  - its SAN dNSName is mtls.prod.connectors.openai.com.

The server checks exactly that on each request and records the result. A request
without that certificate (stdio, a plain HTTPS client, a caller that types
"source: openai" into a tool argument) is recorded as source "unverified".

What this establishes: the TLS peer held a private key OpenAI certified for its
connector platform. It does not establish which model produced the text, and a
third party later sees only memdb's signed statement that the check passed (a TLS
handshake can't be replayed to them).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import verification

OPENAI_CONNECTOR_SAN = "mtls.prod.connectors.openai.com"


def _fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


@dataclass
class OpenAITrust:
    """Trust roots for OpenAI's connector mTLS certificates.

    Load from a PEM bundle holding OpenAI's root CA and the Connectors mTLS
    intermediate (both published at developers.openai.com/plugins/mtls/). The
    operator downloads and pins these; they are public certificates, not secrets.
    """

    roots: list[x509.Certificate]
    intermediates: list[x509.Certificate]
    expected_san: str = OPENAI_CONNECTOR_SAN

    @classmethod
    def from_pem_bundle(cls, pem: bytes, expected_san: str = OPENAI_CONNECTOR_SAN) -> "OpenAITrust":
        certs = x509.load_pem_x509_certificates(pem)
        roots = [c for c in certs if c.issuer == c.subject]
        intermediates = [c for c in certs if c.issuer != c.subject]
        if not roots:
            raise ValueError("OpenAI CA bundle has no self-signed root certificate")
        return cls(roots=roots, intermediates=intermediates, expected_san=expected_san)

    @classmethod
    def from_file(cls, path: str) -> "OpenAITrust":
        with open(path, "rb") as fh:
            return cls.from_pem_bundle(fh.read())

    def evaluate(
        self,
        leaf: Optional[x509.Certificate],
        presented_chain: Optional[list[x509.Certificate]] = None,
        *,
        transport: str,
        now: Optional[dt.datetime] = None,
    ) -> dict[str, Any]:
        """Return channel evidence for one request."""
        evidence: dict[str, Any] = {"transport": transport, "openai_verified": False}
        if leaf is None:
            evidence["reason"] = "no client certificate presented"
            return evidence

        evidence["client_cert_sha256"] = _fingerprint(leaf)
        evidence["client_cert_der_b64"] = base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode("ascii")
        try:
            builder = verification.PolicyBuilder().store(verification.Store(self.roots))
            builder = builder.time(now or dt.datetime.now(dt.timezone.utc))
            verifier = builder.build_client_verifier()
            verified = verifier.verify(leaf, [*(presented_chain or []), *self.intermediates])
        except verification.VerificationError as exc:
            evidence["reason"] = f"client certificate does not chain to the OpenAI connector CA: {exc}"
            return evidence

        sans = [n.value for n in (verified.subjects or []) if isinstance(n, x509.DNSName)]
        evidence["client_cert_san"] = sans
        if self.expected_san not in sans:
            evidence["reason"] = f"client certificate SAN is not {self.expected_san}"
            return evidence

        evidence["openai_verified"] = True
        evidence["verified_chain_sha256"] = [_fingerprint(c) for c in verified.chain]
        evidence["client_cert_not_after"] = leaf.not_valid_after_utc.isoformat().replace("+00:00", "Z")
        evidence["checked"] = [
            "chains to pinned OpenAI connector CA",
            "extendedKeyUsage clientAuth",
            f"SAN dNSName {self.expected_san}",
            "within validity period",
        ]
        return evidence


def cert_from_der(der: Optional[bytes]) -> Optional[x509.Certificate]:
    return x509.load_der_x509_certificate(der) if der else None


def cert_from_proxy_header(value: Optional[str]) -> Optional[x509.Certificate]:
    """Parse a URL-escaped PEM client cert as forwarded by nginx ($ssl_client_escaped_cert) or Caddy."""
    if not value:
        return None
    pem = urllib.parse.unquote(value).encode("ascii")
    return x509.load_pem_x509_certificate(pem)


def stdio_evidence() -> dict[str, Any]:
    return {
        "transport": "stdio",
        "openai_verified": False,
        "reason": "local stdio process; the operator's config names the client, nothing verifies it",
    }
