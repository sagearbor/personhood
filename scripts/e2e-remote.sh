#!/usr/bin/env bash
# scripts/e2e-remote.sh — round-1 (email-only) enrollment proof against a
# DEPLOYED, remote issuer, the way a friend's phone would use it, followed by
# the same verification an integrator would run.
#
#   1. GET  /v1/methods, /v1/config          -- sanity + discover the invite gate
#   2. POST /enrollment/start                -- with an invite code if the issuer requires one
#   3. POST /v1/methods/email/begin          -- reads magic_link_url back (requires the
#                                                deployment to run with DEV_EXPOSE_CHALLENGE_SECRETS=1,
#                                                since there is no real inbox to poll here)
#   4. GET  the magic link                   -- "clicks" it
#   5. POST /v1/credentials/issue            -- receive the signed W3C VC
#   6. tools/verify-credential               -- signature + revocation + policy:
#        docs/policies/round1-email.yaml   must PASS   (exit 0)
#        docs/policies/default-floor.yaml  must FAIL   (exit 1, code anchor_missing)
#
# Usage:
#   bash scripts/e2e-remote.sh <issuer-url> [invite-code]
#
# Needs: go 1.22+, curl, python3. Builds tools/verify-credential into a
# temp dir (removed on exit unless E2E_KEEP=1). No network access beyond the
# issuer URL you pass in.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash scripts/e2e-remote.sh <issuer-url> [invite-code]

  issuer-url    base URL of a deployed Personhood issuer, e.g.
                https://personhood-issuer-XXXXXXXXXXXX.us-central1.run.app
  invite-code   optional; required if the issuer was deployed with
                ENROLLMENT_INVITE_CODE set (GET /v1/config reports this as
                invite_code_required=true)

Env:
  E2E_KEEP=1    keep the temp work dir + built binaries on exit; path is printed.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  [[ $# -lt 1 ]] && exit 1
  exit 0
fi

BASE="${1%/}"
INVITE="${2:-}"

cd "$(dirname "$0")/.."
ROOT="$PWD"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/personhood-e2e-remote.XXXXXX")
cleanup() {
  if [[ "${E2E_KEEP:-0}" == "1" ]]; then
    echo "e2e-remote: kept work dir $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

die() { echo "FAIL: $*" >&2; exit 1; }
jget() {
  python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d = d[k]
print(d)
' "$1" "$2"
}

command -v go >/dev/null 2>&1 || die "go toolchain not found"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

echo "== build tools/verify-credential =="
(cd "$ROOT/tools/verify-credential" && go build -o "$WORK/verify" .)

echo "== GET /v1/methods =="
curl -sf "$BASE/v1/methods" >"$WORK/methods.json" || die "GET /v1/methods failed"
echo "methods: $(python3 -c 'import json,sys; print(",".join(m["id"] for m in json.load(sys.stdin)["methods"]))' <"$WORK/methods.json")"

echo "== GET /v1/config =="
if curl -sf "$BASE/v1/config" >"$WORK/config.json" 2>/dev/null; then
  echo "config: $(cat "$WORK/config.json")"
  INVITE_REQUIRED=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("invite_code_required", False))' <"$WORK/config.json")
  if [[ "$INVITE_REQUIRED" == "True" && -z "$INVITE" ]]; then
    die "issuer requires an invite code (GET /v1/config: invite_code_required=true) but none was given"
  fi
else
  echo "config: /v1/config not reachable (older revision without the endpoint?) -- continuing without it"
fi

echo "== POST /enrollment/start =="
BODY='{"platform":"e2e-remote"}'
[[ -n "$INVITE" ]] && BODY="{\"platform\":\"e2e-remote\",\"invite_code\":\"$INVITE\"}"
if ! curl -sf -X POST "$BASE/enrollment/start" -H 'Content-Type: application/json' -d "$BODY" >"$WORK/start.json"; then
  RESP=$(curl -s -X POST "$BASE/enrollment/start" -H 'Content-Type: application/json' -d "$BODY")
  die "enrollment/start failed: $RESP"
fi
SESSION=$(jget "$WORK/start.json" session_id)
[[ -n "$SESSION" ]] || die "no session_id in start response"
echo "session=$SESSION"

EMAIL="e2e-$(date +%s)@example.com"
echo "== POST /v1/methods/email/begin ($EMAIL) =="
curl -sf -X POST "$BASE/v1/methods/email/begin" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION\",\"user_input\":\"$EMAIL\"}" >"$WORK/begin.json" \
  || die "email/begin failed"
LINK=$(jget "$WORK/begin.json" challenge.payload.magic_link_url) \
  || die "no magic_link_url in begin response (is DEV_EXPOSE_CHALLENGE_SECRETS=1 on this deployment?)"
echo "magic link host: $(echo "$LINK" | cut -d/ -f3)"

echo "== GET the magic link =="
curl -sf "$LINK" >"$WORK/click.html" || die "GET magic link failed"
grep -q "Email verified" "$WORK/click.html" || die "landing page did not say 'Email verified'"
echo "landing page: Email verified"

echo "== GET /v1/sessions/{id} =="
curl -sf "$BASE/v1/sessions/$SESSION" >"$WORK/sess.json" || die "GET session failed"
echo "session after click: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print({k:v for k,v in d.items() if k in ("status","completed_methods","methods")})' "$WORK/sess.json")"

echo "== POST /v1/credentials/issue =="
curl -sf -X POST "$BASE/v1/credentials/issue" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION\"}" >"$WORK/issued.json" || die "credentials/issue failed"
python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["credential"], open(sys.argv[2],"w"), indent=2)' \
  "$WORK/issued.json" "$WORK/credential.json"
echo "issuer: $(jget "$WORK/credential.json" issuer)"

echo "== verify: round1-email.yaml must PASS =="
set +e
"$WORK/verify" -cred "$WORK/credential.json" -policy "$ROOT/docs/policies/round1-email.yaml" -issuer-url "$BASE" >"$WORK/v1.txt" 2>&1
RC1=$?
set -e
echo "exit $RC1 :: $(head -c 200 "$WORK/v1.txt" | tr '\n' ' ')"
[[ "$RC1" -eq 0 ]] || die "round1-email.yaml should have been accepted"

echo "== verify: default-floor.yaml must FAIL with anchor_missing =="
set +e
"$WORK/verify" -cred "$WORK/credential.json" -policy "$ROOT/docs/policies/default-floor.yaml" -issuer-url "$BASE" >"$WORK/v2.txt" 2>&1
RC2=$?
set -e
echo "exit $RC2 :: $(head -c 200 "$WORK/v2.txt" | tr '\n' ' ')"
[[ "$RC2" -eq 1 ]] || die "default-floor.yaml should have been rejected (exit 1), got $RC2"
grep -q anchor_missing "$WORK/v2.txt" || die "expected code anchor_missing, got: $(cat "$WORK/v2.txt")"

[[ "${E2E_KEEP:-0}" == "1" ]] && echo "credential: $WORK/credential.json"
echo
echo "e2e-remote PASSED"
