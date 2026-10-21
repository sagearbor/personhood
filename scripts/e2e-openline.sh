#!/usr/bin/env bash
# scripts/e2e-openline.sh — the Personhood → OpenLine handshake, against the
# live deployments, without touching OpenLine's ledger by default.
#
#   1. The issuer's current signing key (/.well-known/did.json) is the key
#      OpenLine pinned (OPENLINE_TRUSTED_ISSUERS on the openline-seed Cloud
#      Run service — read with gcloud; skipped with a warning if gcloud can't
#      see it). A rotated issuer key silently breaks every UBI claim, so this
#      is the check that matters most.
#   2. OpenLine's /health says personhood is enabled, names the issuer DID as
#      trusted, and runs the round1-email policy set.
#   3. A fresh credential from the live issuer, TAMPERED (one claim changed
#      after signing), is refused by POST /commons/claim. Refused requests
#      don't reach the ledger, so this is safe to run on a schedule.
#   4. Only with OPENLINE_E2E_CLAIM=1: the untampered credential claims UBI
#      (200) and a second claim is refused as a duplicate (409). This mints
#      real testnet OLN to the seed's own address, so it is opt-in.
#
# Usage:
#   PERSONHOOD_INVITE_CODE=... bash scripts/e2e-openline.sh
#
# Env:
#   ISSUER    default https://personhood-issuer-664594784582.us-central1.run.app
#   OPENLINE  default https://openline-seed-664594784582.us-central1.run.app
#   PERSONHOOD_INVITE_CODE   required when the issuer is invite-gated
#   OPENLINE_PROJECT / OPENLINE_SERVICE / OPENLINE_REGION   for the pin check
#     (default arborfam-hub / openline-seed / us-central1)
#
# Needs: curl, python3; gcloud for step 1. The issuer must be in test mode
# (DEV_EXPOSE_CHALLENGE_SECRETS=1) so the magic link comes back over the API.
set -euo pipefail

ISSUER="${ISSUER:-https://personhood-issuer-664594784582.us-central1.run.app}"
OPENLINE="${OPENLINE:-https://openline-seed-664594784582.us-central1.run.app}"
INVITE="${PERSONHOOD_INVITE_CODE:-}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

die() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $* =="; }
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))" "$@"; }

step "issuer DID document"
curl -sf "$ISSUER/.well-known/did.json" >"$WORK/did.json" || die "GET did.json"
DID=$(json "$WORK/did.json" 'd["id"]')
KEY=$(json "$WORK/did.json" 'd["verificationMethod"][0]["publicKeyJwk"]["x"]')
echo "issuer $DID key $KEY"

step "pinned key on OpenLine matches the issuer's current key"
if command -v gcloud >/dev/null 2>&1 && PIN=$(gcloud run services describe "${OPENLINE_SERVICE:-openline-seed}" \
    --region "${OPENLINE_REGION:-us-central1}" --project "${OPENLINE_PROJECT:-arborfam-hub}" --format=json 2>/dev/null \
    | python3 -c 'import json,sys; e=json.load(sys.stdin)["spec"]["template"]["spec"]["containers"][0].get("env",[]); print(next((x.get("value","") for x in e if x["name"]=="OPENLINE_TRUSTED_ISSUERS"),""))'); then
  [[ -n "$PIN" ]] || die "openline-seed has no OPENLINE_TRUSTED_ISSUERS"
  case ",$PIN," in
    *",$DID=$KEY,"*) echo "pinned: match" ;;
    *) die "OpenLine pins '$PIN' but the issuer serves $DID=$KEY — redeploy openline (cmd/openline-node/scripts/deploy-cloudrun.sh)" ;;
  esac
else
  echo "WARN: gcloud can't read the openline-seed service; skipping the pin comparison"
fi

step "OpenLine /health"
curl -sf "$OPENLINE/health" >"$WORK/health.json" || die "GET openline /health"
[[ $(json "$WORK/health.json" 'd.get("personhoodEnabled")') == "True" ]] || die "personhood integration disabled on OpenLine"
[[ $(json "$WORK/health.json" '"'"$DID"'" in d.get("personhoodTrustedIssuers",[])') == "True" ]] || die "OpenLine does not trust $DID"
echo "policy set: $(json "$WORK/health.json" 'd.get("personhoodPolicy")')"
SELF=$(json "$WORK/health.json" 'd["selfAddress"]')

step "fresh credential from the live issuer"
python3 -c 'import json,sys; print(json.dumps({"platform":"e2e-openline","invite_code":sys.argv[1]} if sys.argv[1] else {"platform":"e2e-openline"}))' "$INVITE" >"$WORK/start.json"
curl -sf -X POST "$ISSUER/enrollment/start" -H 'Content-Type: application/json' --data-binary @"$WORK/start.json" >"$WORK/sess.json" \
  || die "enrollment/start (invite code missing or wrong?)"
SESSION=$(json "$WORK/sess.json" 'd["session_id"]')
curl -sf -X POST "$ISSUER/v1/methods/email/begin" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION\",\"user_input\":\"e2e-openline-$(date +%s)@example.com\"}" >"$WORK/begin.json" || die "email begin"
LINK=$(json "$WORK/begin.json" 'd["challenge"]["payload"].get("magic_link_url","")')
[[ -n "$LINK" ]] || die "no magic link returned — is the issuer in test mode?"
curl -sf "$LINK" | grep -q "Email verified" || die "magic link click"
curl -sf -X POST "$ISSUER/v1/credentials/issue" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SESSION\"}" >"$WORK/issue.json" || die "credentials/issue"
python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["credential"], open(sys.argv[2],"w"))' "$WORK/issue.json" "$WORK/cred.json"
echo "credential $(json "$WORK/cred.json" 'd["id"]')"

claim() { # $1 = credential file; prints HTTP status, body to $WORK/claim.out
  python3 -c 'import json,sys; print(json.dumps({"address":sys.argv[2],"credential":json.load(open(sys.argv[1]))}))' "$1" "$SELF" >"$WORK/claim.json"
  curl -s -o "$WORK/claim.out" -w '%{http_code}' -X POST "$OPENLINE/commons/claim" \
    -H 'Content-Type: application/json' --data-binary @"$WORK/claim.json"
}

step "tampered credential is refused"
python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); c["expirationDate"]="2099-01-01T00:00:00Z"; json.dump(c,open(sys.argv[2],"w"))' "$WORK/cred.json" "$WORK/tampered.json"
CODE=$(claim "$WORK/tampered.json")
case "$CODE" in
  2*|409) die "tampered credential got HTTP $CODE: $(cat "$WORK/claim.out")" ;;
  *) echo "refused with HTTP $CODE: $(head -c 200 "$WORK/claim.out")" ;;
esac

if [[ "${OPENLINE_E2E_CLAIM:-}" == "1" ]]; then
  step "OPENLINE_E2E_CLAIM=1: real claim, then duplicate"
  CODE=$(claim "$WORK/cred.json")
  [[ "$CODE" == 200 ]] || die "claim got HTTP $CODE: $(cat "$WORK/claim.out")"
  echo "claimed: $(head -c 200 "$WORK/claim.out")"
  CODE=$(claim "$WORK/cred.json")
  [[ "$CODE" == 409 ]] || die "duplicate claim got HTTP $CODE, want 409: $(cat "$WORK/claim.out")"
  echo "duplicate refused (409)"
else
  echo "(skipping the ledger-mutating claim; set OPENLINE_E2E_CLAIM=1 to run it)"
fi

echo
echo "e2e-openline PASSED"
