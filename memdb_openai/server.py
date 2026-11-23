"""Minimal MCP server (JSON-RPC 2.0) exposing memdb to OpenAI clients.

Transports:
  - Streamable HTTP (POST /mcp, JSON responses). Optionally terminates TLS itself and
    requests the OpenAI connector client certificate, or sits behind a TLS proxy that
    forwards the verified client cert in a header (loopback-bound only).
  - stdio (newline-delimited JSON), for a local Codex process. Writes over stdio are
    always recorded as source "unverified".

Tools: search, recall, learn, get_provenance. `learn` never accepts a source field;
the source is set from the channel evidence of the request.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import ssl
import sys
from contextlib import closing
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import serialization

import memdb

from . import provenance
from .channel import OpenAITrust, cert_from_der, cert_from_proxy_header, stdio_evidence

SERVER_NAME = "memdb-openai"
SERVER_VERSION = "0.1.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")

LEARN_FIELDS = {"type", "title", "summary", "key", "priority", "tags", "evidence", "source_refs"}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "search",
        "title": "Search memory",
        "description": "Full-text search over memdb messages and durable learned memories. Each learned hit carries its provenance (source, record hash, onchain anchor if any).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search terms"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "recall",
        "title": "Recall durable memories",
        "description": "Return durable learned memories (decisions, preferences, lessons, commitments, projects, people, handoffs), newest first, optionally filtered by a query. Each result says which source wrote it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Optional search terms"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "learn",
        "title": "Save a durable memory",
        "description": "Record one durable memory. memdb attaches a signed provenance record whose source is determined by how this request reached the server, not by any argument.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": sorted(memdb.LEARNED_MEMORY_TYPES)},
                "title": {"type": "string"},
                "summary": {"type": "string"},
                "key": {"type": "string", "description": "Stable slug; defaults to the title"},
                "priority": {"type": "string", "enum": ["red", "yellow", "green"]},
                "tags": {"type": "array", "items": {"type": "string"}},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "source_refs": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["type", "title"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    },
    {
        "name": "get_provenance",
        "title": "Get a memory's proof",
        "description": "Return the proof bundle for a memory: content, signed provenance record, and Merkle inclusion proof plus anchor transaction when anchored.",
        "inputSchema": {
            "type": "object",
            "properties": {"memory_id": {"type": "integer"}},
            "required": ["memory_id"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
]


class ToolError(Exception):
    pass


@dataclass
class RequestContext:
    channel: dict[str, Any]
    authorization: dict[str, Any]


@dataclass
class McpApp:
    db_path: str
    attester: provenance.Attester
    _initialized_db: bool = field(default=False, init=False)

    def _connect(self):
        con = memdb.connect(self.db_path)
        if not self._initialized_db:
            memdb.init_db(con)
            provenance.init_provenance(con)
            self._initialized_db = True
        return con

    # -- JSON-RPC ---------------------------------------------------------

    def handle(self, message: Any, ctx: RequestContext) -> Optional[dict[str, Any]]:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "method" not in message:
            return _rpc_error(message.get("id") if isinstance(message, dict) else None, -32600, "Invalid Request")
        msg_id = message.get("id")
        is_notification = "id" not in message
        method = message["method"]
        params = message.get("params") or {}
        try:
            if method == "initialize":
                result = self._initialize(params)
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                result = self._call_tool(params, ctx)
            elif method.startswith("notifications/"):
                return None
            else:
                return None if is_notification else _rpc_error(msg_id, -32601, f"Method not found: {method}")
        except ToolError as exc:
            result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
        except Exception as exc:  # keep the server alive; report as JSON-RPC error
            return None if is_notification else _rpc_error(msg_id, -32603, f"Internal error: {exc}")
        return None if is_notification else {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "memdb is a shared durable memory. Use recall/search before answering questions about past "
                "decisions; use learn to save stable decisions, preferences, lessons and commitments. Every write gets "
                "a signed provenance record; its source is set by the server from the connection, not by you."
            ),
        }

    def _call_tool(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            raise ToolError("arguments must be an object")
        handler: Optional[Callable[[dict[str, Any], RequestContext], Any]] = {
            "search": self._tool_search,
            "recall": self._tool_recall,
            "learn": self._tool_learn,
            "get_provenance": self._tool_get_provenance,
        }.get(name)
        if handler is None:
            raise ToolError(f"Unknown tool: {name}")
        payload = handler(args, ctx)
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
            "structuredContent": payload,
        }

    # -- tools ------------------------------------------------------------

    @staticmethod
    def _limit(args: dict[str, Any]) -> int:
        try:
            return max(1, min(50, int(args.get("limit", 10))))
        except (TypeError, ValueError):
            raise ToolError("limit must be an integer")

    def _annotate(self, con, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        event_ids = [r["id"] for r in results if r.get("type") == "event"]
        labels = provenance.provenance_summary(con, event_ids)
        for r in results:
            if r.get("type") == "event":
                r["provenance"] = labels.get(r["id"])  # None = no provenance record (e.g. ingested or CLI write)
        return results

    def _tool_search(self, args: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        query = str(args.get("query") or "").strip()
        if not query:
            raise ToolError("query is required")
        with closing(self._connect()) as con:
            results = memdb.query_items(con, query, scope={}, limit=self._limit(args), include_events=True)
            return {"query": query, "results": self._annotate(con, results)}

    def _tool_recall(self, args: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        query = str(args.get("query") or "").strip()
        limit = self._limit(args)
        with closing(self._connect()) as con:
            if query:
                hits = memdb.query_items(con, query, scope={}, limit=limit * 4, include_events=True)
                results = [h for h in hits if h.get("type") == "event" and h.get("kind") == "learned"][:limit]
            else:
                rows = con.execute(
                    """
                    SELECT 'event' AS item_type, e.id, e.ts_ms, e.session_id, e.session_key,
                      NULL AS chat_app, NULL AS chat_id, NULL AS thread_id, NULL AS author_role, NULL AS author_name,
                      e.kind, e.name, e.text, e.source_file, e.source_line, NULL AS rank
                    FROM events e WHERE e.kind = 'learned' ORDER BY e.ts_ms DESC, e.id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                results = [memdb._row_to_recall_result(r) for r in rows]
            return {"query": query or None, "results": self._annotate(con, results)}

    def _tool_learn(self, args: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        unknown = set(args) - LEARN_FIELDS
        if unknown:
            raise ToolError(f"Unsupported arguments: {', '.join(sorted(unknown))}")
        with closing(self._connect()) as con:
            try:
                result = memdb.record_learned(
                    con,
                    memory_type=args.get("type"),
                    title=args.get("title"),
                    summary=args.get("summary"),
                    key=args.get("key"),
                    priority=args.get("priority"),
                    tags=args.get("tags"),
                    evidence=args.get("evidence"),
                    source_refs=args.get("source_refs"),
                    commit=False,
                )
                attested = provenance.attest_event(
                    con,
                    event_id=result["id"],
                    channel=ctx.channel,
                    authorization=ctx.authorization,
                    attester=self.attester,
                )
                con.commit()
            except memdb.LearnError as exc:
                con.rollback()
                raise ToolError(str(exc))
            except Exception:
                con.rollback()
                raise
        return {
            **result,
            "provenance": {
                "source": attested["record"]["source"],
                "record_hash": attested["record_hash"],
                "anchored": False,
            },
        }

    def _tool_get_provenance(self, args: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        try:
            memory_id = int(args.get("memory_id"))
        except (TypeError, ValueError):
            raise ToolError("memory_id must be an integer")
        with closing(self._connect()) as con:
            try:
                return provenance.build_bundle(con, memory_id)
            except LookupError as exc:
                raise ToolError(str(exc))


def _rpc_error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


# ---------------------------------------------------------------------------
# Authorization (who may use this memdb), separate from source (who is calling)
# ---------------------------------------------------------------------------

@dataclass
class AuthConfig:
    """Hashes of bearer tokens and path secrets, each mapped to a subject label.

    Loaded from a JSON file kept outside the repo:
      {"bearer_sha256": {"<hex>": "mitya"}, "path_secret_sha256": {"<hex>": "mitya"}}

    Bearer tokens suit Codex (`bearer_token_env_var`). ChatGPT does not send custom
    API keys, so until memdb runs its own OAuth server a ChatGPT connector uses a
    secret URL path (/mcp/<secret>) together with the OpenAI mTLS check.
    """

    bearer_sha256: dict[str, str] = field(default_factory=dict)
    path_secret_sha256: dict[str, str] = field(default_factory=dict)
    allow_anonymous: bool = False

    @classmethod
    def from_file(cls, path: str) -> "AuthConfig":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(
            bearer_sha256={k.lower(): v for k, v in (data.get("bearer_sha256") or {}).items()},
            path_secret_sha256={k.lower(): v for k, v in (data.get("path_secret_sha256") or {}).items()},
        )

    @staticmethod
    def _lookup(table: dict[str, str], secret: str) -> Optional[str]:
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        for known, subject in table.items():
            if hmac.compare_digest(known, digest):
                return subject
        return None

    def authorize(self, path: str, authorization_header: Optional[str]) -> Optional[dict[str, Any]]:
        if authorization_header and authorization_header.lower().startswith("bearer "):
            subject = self._lookup(self.bearer_sha256, authorization_header[7:].strip())
            if subject:
                return {"method": "bearer", "subject": subject}
        parts = [p for p in path.split("?")[0].split("/") if p]
        if len(parts) == 2 and parts[0] == "mcp":
            subject = self._lookup(self.path_secret_sha256, parts[1])
            if subject:
                return {"method": "path-secret", "subject": subject}
        if self.allow_anonymous:
            return {"method": "none", "subject": None}
        return None


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

def make_http_server(
    app: McpApp,
    *,
    host: str,
    port: int,
    auth: AuthConfig,
    trust: Optional[OpenAITrust],
    tls_cert: Optional[str] = None,
    tls_key: Optional[str] = None,
    client_cert_header: Optional[str] = None,
) -> ThreadingHTTPServer:
    if client_cert_header and host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("--client-cert-header is only honoured on a loopback bind behind a TLS proxy")

    class Handler(BaseHTTPRequestHandler):
        server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

        def _send_json(self, status: int, body: Optional[dict[str, Any]]) -> None:
            data = b"" if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _channel(self) -> dict[str, Any]:
            leaf = None
            transport = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
            if client_cert_header:
                leaf = cert_from_proxy_header(self.headers.get(client_cert_header))
                transport = "https-proxy-mtls"
            elif isinstance(self.connection, ssl.SSLSocket):
                leaf = cert_from_der(self.connection.getpeercert(binary_form=True))
                transport = "https-mtls" if leaf is not None else "https"
            if trust is None:
                return {"transport": transport, "openai_verified": False, "reason": "no OpenAI CA configured"}
            return trust.evaluate(leaf, transport=transport)

        def do_GET(self) -> None:
            self._send_json(405, {"error": "use POST for MCP requests"})

        def do_POST(self) -> None:
            if not self.path.split("?")[0].startswith("/mcp"):
                self._send_json(404, {"error": "not found"})
                return
            authz = auth.authorize(self.path, self.headers.get("Authorization"))
            if authz is None:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                message = json.loads(self.rfile.read(length) or b"null")
            except (ValueError, json.JSONDecodeError):
                self._send_json(400, _rpc_error(None, -32700, "Parse error"))
                return
            try:
                ctx = RequestContext(channel=self._channel(), authorization=authz)
            except ValueError as exc:
                self._send_json(400, {"error": f"bad client certificate: {exc}"})
                return
            response = app.handle(message, ctx)
            if response is None:
                self._send_json(202, None)
            else:
                self._send_json(200, response)

    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    class Server(ThreadingHTTPServer):
        address_family = family
        daemon_threads = True

    httpd = Server((host, port), Handler)
    if tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_cert, tls_key)
        if trust is not None:
            # Ask for a client cert but don't require one: non-OpenAI clients still work, as "unverified".
            ctx.verify_mode = ssl.CERT_OPTIONAL
            for cert in [*trust.roots, *trust.intermediates]:
                ctx.load_verify_locations(cadata=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


# ---------------------------------------------------------------------------
# stdio transport
# ---------------------------------------------------------------------------

def serve_stdio(app: McpApp, stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    ctx = RequestContext(channel=stdio_evidence(), authorization={"method": "local-process", "subject": None})
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response: Optional[dict[str, Any]] = _rpc_error(None, -32700, "Parse error")
        else:
            response = app.handle(message, ctx)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            stdout.flush()
