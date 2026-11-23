# memdb OpenAI plugin

An MCP server and plugin package that let OpenAI agents (ChatGPT, Codex) read and write
memdb. Every memory written through it gets a signed provenance record, and those records
are committed to Bitcoin SV under a Merkle root. A reader of a shared memdb can then tell
which channel wrote a memory, when it was written, and that nobody changed the memory or
its source label afterwards.

Code: [`memdb_openai/`](../../memdb_openai). CLI: [`bin/memdb-openai`](../../bin/memdb-openai).
Demo: [`scripts/openai_plugin_demo.sh`](../../scripts/openai_plugin_demo.sh).

## What the proof says, exactly

**What it proves**
- **Integrity:** the memory's content is byte-for-byte what memdb attested. Any edit
  breaks the content hash.
- **Labels:** the `source` label, the channel evidence and the receive time were signed by
  memdb's attestation key and have not changed since.
- **Time** (after a real anchor): the record existed no later than the block that contains
  the anchor transaction.
- **What `source: "openai"` means:** on the request that wrote the memory, memdb's server
  saw a TLS client certificate that chains to OpenAI's Connectors mTLS CA, is valid for
  client authentication, and has the SAN `mtls.prod.connectors.openai.com`. OpenAI
  documents this certificate as how ChatGPT identifies itself to MCP servers
  ([docs](https://developers.openai.com/plugins/build/auth)).

**What it does not prove**
- **Authorship:** it does not prove which model, if any, generated the text. OpenAI does
  not sign model outputs or tool-call arguments. Nothing documented lets anyone verify
  that "an OpenAI model wrote this".
- **Independence from memdb:** the channel check is memdb's signed statement. A third
  party cannot replay the TLS handshake. They trust that memdb's attestation key checked
  the certificate. What they can check themselves is that the statement was not altered
  after signing, and, once anchored, after the block time.
- **Completeness:** it does not prove that memdb recorded every write. It proves only that
  the attested writes are unaltered.
- **Dry-run anchors:** a dry-run anchor proves no time at all, because the transaction was
  never broadcast.

The `source` field is never taken from the caller. `learn` rejects unknown arguments, so
a tool call carrying `"source": "openai"` is refused. A request without the OpenAI
certificate is recorded as `source: "unverified"`. That covers stdio, plain HTTPS, and
any other client.

## Pieces

| Piece | Where | Notes |
|---|---|---|
| MCP server | `memdb_openai/server.py` | Tools: `search`, `recall`, `learn`, `get_provenance`. Transports: Streamable HTTP (`POST /mcp`) and stdio. |
| Channel check | `memdb_openai/channel.py` | Verifies the OpenAI connector client cert against a pinned CA bundle. |
| Provenance record | `memdb_openai/provenance.py` | Canonical JSON, SHA-256, Ed25519 signature, Merkle tree, append-only tables. |
| Anchor | `memdb_openai/anchor.py` | BSV tx with output `OP_FALSE OP_RETURN "memdb.anchor.v1" <merkle_root> <attester_pubkey>`. |
| Verify | `memdb_openai/verify.py` | Checks content hash → signature by the pinned key → Merkle inclusion → anchor tx. Optionally also the network copy and the live db row. |
| Package | `plugins/memdb-openai/plugin.json`, `mcp.json` | Agent Plugins 1.0 layout with `extensions.com.openai`. |

### Provenance record (`memdb.provenance.v1`)

```json
{
  "schema": "memdb.provenance.v1",
  "memory": {"table": "events", "id": 42},
  "content_sha256": "<sha256 of canonical memdb.content.v1 object>",
  "source": "openai",
  "channel": {
    "transport": "https-mtls",
    "openai_verified": true,
    "client_cert_sha256": "...",
    "client_cert_der_b64": "...",
    "client_cert_san": ["mtls.prod.connectors.openai.com"],
    "verified_chain_sha256": ["...", "...", "..."],
    "checked": ["chains to pinned OpenAI connector CA", "extendedKeyUsage clientAuth", "..."]
  },
  "authorization": {"method": "bearer", "subject": "mitya"},
  "received_at": "2026-11-23T04:17:08.736Z",
  "attester": {"alg": "ed25519", "public_key": "<hex>"}
}
```

- **Hashing and signing:** `record_hash` is the SHA-256 of the canonical JSON (sorted keys,
  no whitespace, UTF-8). The Ed25519 signature covers those same bytes.
- **Merkle tree:** leaves are `sha256(0x00 || record_hash)` and nodes are
  `sha256(0x01 || left || right)`. An odd node is promoted without duplication.

### Storage

New tables sit next to `events` in the same SQLite file:
- `provenance_records`
- `provenance_anchors`
- `provenance_anchor_leaves`

Existing memdb rows are never rewritten. Triggers enforce this:
- **Provenance tables:** `UPDATE` and `DELETE` abort on all three.
- **Attested `events` rows:** content columns can't be updated, and the row can't be
  deleted. memdb's own `origin_message_id` migration still runs.
- **One record per event:** `event_id` is `UNIQUE`, so a second, relabelled record can't be
  added.

## Who may call it vs. who is calling

These are separate questions. **Authorization** decides who may use this memdb. It is
configured in a JSON file kept outside the repo, holding SHA-256 hashes only:

```json
{"bearer_sha256": {"<sha256 of token>": "mitya"}, "path_secret_sha256": {"<sha256 of secret>": "mitya"}}
```

- **Codex:** sends a bearer token (`bearer_token_env_var` in its MCP config).
- **ChatGPT:** doesn't send custom API keys. Until memdb runs its own OAuth server, a
  ChatGPT connector uses a secret URL path, `https://<host>/mcp/<secret>`, together with the
  mTLS check.

**Source** (who is calling) comes only from the TLS client certificate.

## Running it

```bash
pip install -r requirements-openai.txt      # cryptography; core memdb stays stdlib-only
bin/memdb-openai keygen --out /secure/path/memdb-attest.pem   # 0600, refuses to overwrite
export MEMDB_ATTEST_KEY_FILE=/secure/path/memdb-attest.pem
```

**ChatGPT / remote, with TLS terminated by memdb itself:**

```bash
bin/memdb-openai serve --http 0.0.0.0:8443 \
  --tls-cert fullchain.pem --tls-key privkey.pem \
  --openai-ca openai-connectors-ca.pem \
  --auth-config /secure/path/auth-config.json
```

**Behind a TLS proxy** (nginx, Caddy): have the proxy request and verify the client cert
and forward it URL-escaped in a header. The proxy must also strip that header from inbound
requests. Bind memdb to loopback:

```bash
bin/memdb-openai serve --http 127.0.0.1:8765 --client-cert-header X-Client-Cert \
  --openai-ca openai-connectors-ca.pem --auth-config /secure/path/auth-config.json
```

`openai-connectors-ca.pem` is OpenAI's root CA followed by the Connectors mTLS
intermediate, from `https://developers.openai.com/plugins/mtls/openai-root-ca.pem` and
`.../openai-connectors-mtls-ca.pem`. Download them yourself, check them, and pin them. The
repo doesn't ship them.

**Codex, local stdio** (records `source: "unverified"`, `transport: "stdio"`):

```toml
[mcp_servers.memdb]
command = "/root/memdb/bin/memdb-openai"
args = ["--db", "/root/clawd/memory/memdb.sqlite3", "serve", "--stdio"]
env = { MEMDB_ATTEST_KEY_FILE = "/secure/path/memdb-attest.pem" }
```

**Anchor, export, verify:**

```bash
bin/memdb-openai anchor                       # dry run: builds + signs a tx over a synthetic input, broadcasts nothing
bin/memdb-openai proof 42 --out memory-42.json
bin/memdb-openai verify memory-42.json --attester-key <published hex key>          # exit 0 = ok
bin/memdb-openai verify memory-42.json --attester-key <hex> --fetch-tx --check-db  # + network copy + live row
```

A verifier needs only the bundle and memdb's attestation public key. The operator
publishes that key out of band, for example in a Treechat post or on a web page. It must
be pinned: a bundle re-signed by any other key fails the `attester_pinned` check.

## Turning on real mainnet anchoring

Broadcasting is off unless `anchor --broadcast` is given. It also needs all of the
following from the operator. None of them is in the repo:

1. **A funding key.** A file holding a WIF private key for a small, dedicated BSV address:
   `--funding-key-file`.
2. **A UTXO of that key:** `--utxo <txid>:<vout>:<satoshis>`. P2PKH, as returned by any
   explorer. Each anchor spends it and returns the change to the same address. Pass the
   new change output next time. Tracking UTXOs automatically is not built yet.
3. **A broadcaster.** An ARC endpoint, `--broadcast-url` or `MEMDB_ANCHOR_BROADCAST_URL`,
   for example `https://arc.taal.com`. If it needs a token, set `MEMDB_ANCHOR_ARC_TOKEN`.
4. **A fee rate:** `--fee-rate` in sat/kB. The default is 100, so an anchor costs a few dozen
   satoshis whether it carries 1 record or 10,000.
5. **A published attestation public key**, so verifiers can pin it.

Before the first real broadcast, run `anchor --build-only --funding-key-file ... --utxo ...`.
It builds and signs the real transaction and prints it, without storing or sending
anything, so you can read it first (for example in a tx decoder). Broadcasting is never
exercised by the tests.
