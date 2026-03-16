# memdb

`memdb` is the durable memory backend and CLI used by the OpenClaw workspace.

It is responsible for:
- ingesting session transcripts into SQLite
- backfilling chat and thread scope for recall
- recording durable `learned` events
- generating the typed markdown vault
- cleaning the off-vault memory inbox

## Usage

Run the CLI directly:

```bash
/root/memdb/bin/memdb --help
```

Or use the workspace shim:

```bash
/root/clawd/bin/memdb --help
```

## Data expectations

The live workspace currently uses:
- database: `/root/clawd/memory/memdb.sqlite3`
- vault output: `/root/clawd/memory/vault`
- inbox quarantine: `/root/clawd/state/memory-inbox.md`

## Repo boundary

This repo contains the `memdb` tool itself. The OpenClaw runtime integration lives separately in:

- `/root/openclaw-memdb-memory`
