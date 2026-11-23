#!/usr/bin/env bash
set -u
# Local end-to-end demo of the memdb OpenAI plugin. Uses a throwaway test CA in
# place of OpenAI's connector CA, a throwaway attestation key and a dry-run anchor.
# Nothing is broadcast. Usage: scripts/openai_plugin_demo.sh [workdir]
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="${1:-$(mktemp -d)}"; mkdir -p "$S"; cd "$REPO"
rm -f "$S"/m.db* "$S"/attest.pem
PYTHONPATH="$REPO:$REPO/tests" python3 - "$S" <<'PY'
import hashlib, json, sys
from test_openai_plugin import TestPKI, _key_pem, _pem
S = sys.argv[1]
pki = TestPKI("OpenAI-test")
open(f"{S}/openai-ca.pem", "wb").write(pki.bundle_pem())
open(f"{S}/root.pem", "wb").write(_pem(pki.root))
for name, (cert, key) in (("server", pki.server_leaf()), ("client", pki.leaf())):
    open(f"{S}/{name}.pem", "wb").write(_pem(cert) + _pem(pki.intermediate))
    open(f"{S}/{name}.key", "wb").write(_key_pem(key))
json.dump({"bearer_sha256": {hashlib.sha256(b"demo-token").hexdigest(): "demo"}}, open(f"{S}/auth.json", "w"))
PY
echo "workdir: $S"
M=(bin/memdb-openai --db "$S/m.db" --attest-key "$S/attest.pem")
bin/memdb-openai keygen --out "$S/attest.pem" > "$S/key.json"
PUB=$(python3 -c "import json;print(json.load(open('$S/key.json'))['public_key'])")
echo "attestation public key: $PUB"
"${M[@]}" serve --http 127.0.0.1:18765 --auth-config "$S/auth.json" --openai-ca "$S/openai-ca.pem" --tls-cert "$S/server.pem" --tls-key "$S/server.key" 2>"$S/serve.log" &
SP=$!; sleep 1
prov() { python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['result']['structuredContent']['provenance']))"; }
echo "--- 1. learn over HTTPS with OpenAI (test CA) client cert:"
curl -s --cacert "$S/root.pem" --cert "$S/client.pem" --key "$S/client.key" -H 'Authorization: Bearer demo-token' -H 'Content-Type: application/json' https://127.0.0.1:18765/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"learn","arguments":{"type":"decision","title":"memdb provenance anchors go to BSV"}}}' | prov
echo "--- 2. learn over HTTPS, no client cert:"
curl -s --cacert "$S/root.pem" -H 'Authorization: Bearer demo-token' -H 'Content-Type: application/json' https://127.0.0.1:18765/mcp -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"learn","arguments":{"type":"lesson","title":"plain https caller"}}}' | prov
echo "--- 3. no bearer token -> HTTP $(curl -s -o /dev/null -w '%{http_code}' --cacert "$S/root.pem" -H 'Content-Type: application/json' https://127.0.0.1:18765/mcp -d '{}')"
kill $SP
echo "--- 4. dry-run anchor:"; "${M[@]}" anchor | python3 -c "import json,sys;d=json.load(sys.stdin);d['raw_tx']=d['raw_tx'][:40]+'...';print(json.dumps(d))"
"${M[@]}" proof 1 --out "$S/bundle1.json"; "${M[@]}" proof 2 --out "$S/bundle2.json"
summ() { python3 -c "import json,sys;d=json.load(sys.stdin);print({k:d[k] for k in ('ok','source','claimed_source','anchored')}, 'failed:', [c['check'] for c in d['checks'] if not c['ok']])"; }
echo "--- 5. verify memory 1 (+ live db):"; "${M[@]}" verify "$S/bundle1.json" --attester-key "$PUB" --check-db > "$S/v.out"; echo "exit=$?"; summ < "$S/v.out"
python3 - "$S" <<'PY'
import json,sys; S=sys.argv[1]
b=json.load(open(f"{S}/bundle1.json")); b["content"]["text"]="decision: never anchor"; json.dump(b,open(f"{S}/tampered.json","w"))
b=json.load(open(f"{S}/bundle2.json")); b["record"]["source"]="openai"; b["record"]["channel"]["openai_verified"]=True; json.dump(b,open(f"{S}/relabelled.json","w"))
PY
echo "--- 6. verify tampered content:"; "${M[@]}" verify "$S/tampered.json" --attester-key "$PUB" > "$S/t.out"; echo "exit=$?"; summ < "$S/t.out"
echo "--- 7. verify memory 2 relabelled unverified->openai:"; "${M[@]}" verify "$S/relabelled.json" --attester-key "$PUB" > "$S/r.out"; echo "exit=$?"; summ < "$S/r.out"
echo "--- 8. verify memory 1 against a different trusted key:"; "${M[@]}" verify "$S/bundle1.json" --attester-key "$(printf '11%.0s' {1..32})" > "$S/k.out"; echo "exit=$?"; summ < "$S/k.out"
