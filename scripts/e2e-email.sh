#!/usr/bin/env bash
# scripts/e2e-email.sh — end-to-end proof of the round-1 (email-only) path
# against a REAL locally running issuer, the way a friend would use it:
#
#   1. build + start src/server on a free port with the LogSender
#      (no vendor keys; the magic link is printed to the server log)
#   2. POST /enrollment/start
#   3. POST /v1/methods/email/begin  — and assert the response does NOT leak
#      the magic link to the client
#   4. "click" the link scraped from the server log (what the inbox would do)
#   5. GET /v1/sessions/{id}          — email shows as verified
#   6. POST /v1/credentials/issue     — receive the signed W3C VC
#   7. tools/verify-credential        — signature + revocation + policy:
#        docs/policies/round1-email.yaml  must PASS
#        docs/policies/default-floor.yaml must FAIL with anchor_missing
#
# Usage:  bash scripts/e2e-email.sh            (from anywhere)
# Needs:  go 1.22+, curl, python3. No network access beyond localhost.
# Exit 0 only if every step above held.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
WORK=$(mktemp -d "${TMPDIR:-/tmp}/personhood-e2e.XXXXXX")
LOG="$WORK/server.log"
EMAIL="${E2E_EMAIL:-friend@example.com}"

cleanup() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ "${E2E_KEEP:-0}" = "1" ]; then
    echo "e2e: kept work dir $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die()  { printf '\n\033[31me2e FAILED: %s\033[0m\n' "$*" >&2; echo "--- server log ---" >&2; cat "$LOG" >&2 || true; exit 1; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1]));
for k in sys.argv[2].split("."):
    d = d[int(k)] if isinstance(d,list) else d.get(k)
    if d is None: print(""); sys.exit(0)
print(d if not isinstance(d,(dict,list)) else json.dumps(d))' "$1" "$2"; }

# ---------------------------------------------------------------------------
step "build server + verify-credential"
(cd src/server && go build -o "$WORK/server" ./cmd/server)
(cd tools/verify-credential && go build -o "$WORK/verify" .)

# Free loopback port.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
BASE="http://127.0.0.1:$PORT"

step "start issuer on $BASE (LogSender, secrets NOT exposed to clients)"
SEED=$(cd src/server && go run ./cmd/gen-key 2>/dev/null | grep ISSUER_ED25519 | cut -d= -f2)
[ -n "$SEED" ] || die "gen-key produced no seed"
ISSUER_ED25519_SK_B64="$SEED" SERVER_ADDR="127.0.0.1:$PORT" SERVER_PUBLIC_URL="$BASE" \
  CORS_ALLOWED_ORIGINS="http://localhost:3000" DEV_EXPOSE_CHALLENGE_SECRETS="" \
  "$WORK/server" >"$LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  curl -sf "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "$BASE/healthz" | grep -q '"ok"' || die "server did not become healthy"
echo "healthz ok"

step "methods registered"
curl -sf "$BASE/v1/methods" >"$WORK/methods.json"
grep -q '"email"' "$WORK/methods.json" || die "email method not registered"
python3 -c 'import json,sys; print(", ".join(m["id"] for m in json.load(open(sys.argv[1]))["methods"]))' "$WORK/methods.json"

step "POST /enrollment/start"
curl -sf -X POST "$BASE/enrollment/start" -H 'Content-Type: application/json' \
  -d '{"platform":"e2e"}' >"$WORK/start.json"
SESSION=$(jget "$WORK/start.json" session_id)
HOLDER=$(jget "$WORK/start.json" holder_did)
ISSUER=$(jget "$WORK/start.json" issuer_did)
[ -n "$SESSION" ] || die "no session_id"
echo "session=$SESSION"; echo "holder=$HOLDER"; echo "issuer=$ISSUER"

step "POST /v1/methods/email/begin ($EMAIL)"
curl -sf -X POST "$BASE/v1/methods/email/begin" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION\",\"user_input\":\"$EMAIL\"}" >"$WORK/begin.json"
[ "$(jget "$WORK/begin.json" challenge.type)" = "magic-link" ] || die "expected magic-link challenge"
if grep -q magic_link_url "$WORK/begin.json"; then
  die "SECURITY: /begin returned magic_link_url to the client"
fi
echo "challenge ok; magic link NOT in the client response (good)"

step "scrape the magic link from the server log (stand-in for the inbox)"
LINK=""
for _ in $(seq 1 30); do
  LINK=$(grep -o 'link=http[^ ]*' "$LOG" | tail -1 | cut -d= -f2- || true)
  [ -n "$LINK" ] && break
  sleep 0.1
done
[ -n "$LINK" ] || die "magic link not found in server log"
echo "link=$LINK"

step "GET /v1/sessions/{id} before the click"
curl -sf "$BASE/v1/sessions/$SESSION" >"$WORK/before.json"
[ "$(jget "$WORK/before.json" verified_methods)" = "[]" ] || die "nothing should be verified yet: $(cat "$WORK/before.json")"
echo "verified_methods=[] (as expected)"

step "click the magic link"
curl -sf "$LINK" >"$WORK/click.html"
grep -q "Email verified" "$WORK/click.html" || die "magic-link landing did not say 'Email verified'"
echo "landing page: Email verified"

step "GET /v1/sessions/{id} after the click"
curl -sf "$BASE/v1/sessions/$SESSION" >"$WORK/after.json"
[ "$(jget "$WORK/after.json" verified_methods.0.method_id)" = "email" ] || die "email not verified on session: $(cat "$WORK/after.json")"
echo "verified_methods[0].method_id=email"

step "POST /v1/credentials/issue"
curl -sf -X POST "$BASE/v1/credentials/issue" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION\"}" >"$WORK/issued.json"
python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["credential"], open(sys.argv[2],"w"), indent=2)' "$WORK/issued.json" "$WORK/credential.json"
[ "$(jget "$WORK/credential.json" issuer)" = "$ISSUER" ] || die "issuer mismatch"
[ "$(jget "$WORK/credential.json" credentialSubject.id)" = "$HOLDER" ] || die "holder mismatch"
[ -n "$(jget "$WORK/credential.json" proof.proofValue)" ] || die "credential has no proof"
echo "credential id=$(jget "$WORK/credential.json" id)"

step "verify: round1-email.yaml must PASS (signature + status list + policy)"
"$WORK/verify" -cred "$WORK/credential.json" -policy docs/policies/round1-email.yaml -issuer-url "$BASE" >"$WORK/v1.json" \
  || die "round-1 verification failed: $(cat "$WORK/v1.json")"
cat "$WORK/v1.json"

step "verify: default-floor.yaml must FAIL with anchor_missing"
set +e
"$WORK/verify" -cred "$WORK/credential.json" -policy docs/policies/default-floor.yaml -issuer-url "$BASE" >"$WORK/v2.json"
RC=$?
set -e
[ "$RC" = "1" ] || die "expected exit 1 (rejected) from default-floor policy, got $RC: $(cat "$WORK/v2.json")"
[ "$(jget "$WORK/v2.json" code)" = "anchor_missing" ] || die "expected code anchor_missing: $(cat "$WORK/v2.json")"
echo "code=anchor_missing (as expected — this is what OpenLine's anchor policies will say until an anchor ships)"

step "tamper: a modified credential must be rejected"
python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); c["credentialSubject"]["verifiedMethods"][0]["strength"]=99; json.dump(c,open(sys.argv[2],"w"))' "$WORK/credential.json" "$WORK/tampered.json"
set +e
"$WORK/verify" -cred "$WORK/tampered.json" -policy docs/policies/round1-email.yaml -issuer-url "$BASE" >"$WORK/v3.json"
RC=$?
set -e
[ "$RC" = "1" ] && [ "$(jget "$WORK/v3.json" code)" = "signature_invalid" ] || die "tampered credential was not rejected: rc=$RC $(cat "$WORK/v3.json")"
echo "code=signature_invalid (as expected)"

printf '\n\033[32me2e PASSED\033[0m — email-only enrollment → signed credential → verified against round1-email.yaml\n'
[ "${E2E_KEEP:-0}" = "1" ] && echo "credential: $WORK/credential.json"
exit 0
