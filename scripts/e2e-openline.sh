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
#   3. A fresh credential from the live issuer, bound to a holder key this
#      script generates, TAMPERED (one claim changed after signing) and then
#      presented with a valid holder signature over a fresh node challenge,
#      is refused by POST /commons/claim. Refused requests don't reach the
#      ledger, so this is safe to run on a schedule.
#   4. When the issuer reports identifier_dedup (IDENTIFIER_HMAC_KEY set):
#      enrolling the SAME email again with a DIFFERENT holder key gets the
#      same nullifierBinding commitment back, so OpenLine sees one person.
#   5. Only with OPENLINE_E2E_CLAIM=1: the raw credential without a
#      presentation is refused (403; OpenLine requires holder proof of
#      possession), the presented credential claims UBI (200), a second
#      presentation is refused as a duplicate (409), and with identifier
#      dedup on, the re-enrolled credential is refused as the same person
#      (409). This mints real testnet OLN to the seed's own address, so it is
#      opt-in.
#
# Every request to OpenLine is a Verifiable Presentation: the credential plus
# an ed25519 signature, by the credential's holder did:key, over
# "<challenge>|<domain>" from POST /personhood/challenge.
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
# Needs: curl, python3, node (ed25519 via node:crypto); gcloud for step 1.
# The issuer must be in test mode (DEV_EXPOSE_CHALLENGE_SECRETS=1) so the
# magic link comes back over the API.
set -euo pipefail

ISSUER="${ISSUER:-https://personhood-issuer-664594784582.us-central1.run.app}"
OPENLINE="${OPENLINE:-https://openline-seed-664594784582.us-central1.run.app}"
INVITE="${PERSONHOOD_INVITE_CODE:-}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

die() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $* =="; }
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))" "$@"; }
command -v node >/dev/null 2>&1 || die "node is required (holder-key signing)"

# keygen PEMFILE: writes a fresh ed25519 private key, prints the raw public
# key as base64 (the issuer's holder_public_key_b64).
keygen() {
  node -e 'const c=require("crypto"),fs=require("fs");
    const {publicKey,privateKey}=c.generateKeyPairSync("ed25519");
    fs.writeFileSync(process.argv[1],privateKey.export({type:"pkcs8",format:"pem"}));
    process.stdout.write(publicKey.export({type:"spki",format:"der"}).subarray(12).toString("base64"));' "$1"
}
# sign_b64 PEMFILE MESSAGE: prints the base64 ed25519 signature.
sign_b64() {
  node -e 'const c=require("crypto"),fs=require("fs");
    process.stdout.write(c.sign(null,Buffer.from(process.argv[2],"utf8"),c.createPrivateKey(fs.readFileSync(process.argv[1]))).toString("base64"));' "$1" "$2"
}
# sign PEMFILE MESSAGE: prints the hex ed25519 signature.
sign() {
  node -e 'const c=require("crypto"),fs=require("fs");
    process.stdout.write(c.sign(null,Buffer.from(process.argv[2],"utf8"),c.createPrivateKey(fs.readFileSync(process.argv[1]))).toString("hex"));' "$1" "$2"
}

step "issuer DID document"
curl -sf "$ISSUER/.well-known/did.json" >"$WORK/did.json" || die "GET did.json"
DID=$(json "$WORK/did.json" 'd["id"]')
KEY=$(json "$WORK/did.json" 'd["verificationMethod"][0]["publicKeyJwk"]["x"]')
echo "issuer $DID key $KEY"
curl -sf "$ISSUER/v1/config" >"$WORK/config.json" || die "GET /v1/config"
DEDUP=$(json "$WORK/config.json" 'd.get("identifier_dedup", False)')
echo "identifier_dedup: $DEDUP"

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

# enroll EMAIL NAME: enrolls EMAIL under a fresh holder key; writes
# $WORK/NAME.pem (holder key) and $WORK/NAME.json (credential).
enroll() {
  local email=$1 name=$2 pub session link proof
  pub=$(keygen "$WORK/$name.pem")
  python3 -c 'import json,sys; d={"platform":"e2e-openline","holder_public_key_b64":sys.argv[2]}
if sys.argv[1]: d["invite_code"]=sys.argv[1]
print(json.dumps(d))' "$INVITE" "$pub" >"$WORK/start.json"
  curl -sf -X POST "$ISSUER/enrollment/start" -H 'Content-Type: application/json' --data-binary @"$WORK/start.json" >"$WORK/sess.json" \
    || die "enrollment/start (invite code missing or wrong?)"
  session=$(json "$WORK/sess.json" 'd["session_id"]')
  curl -sf -X POST "$ISSUER/v1/methods/email/begin" -H 'Content-Type: application/json' \
    -d "{\"session_id\":\"$session\",\"user_input\":\"$email\"}" >"$WORK/begin.json" || die "email begin"
  link=$(json "$WORK/begin.json" 'd["challenge"]["payload"].get("magic_link_url","")')
  [[ -n "$link" ]] || die "no magic link returned — is the issuer in test mode?"
  curl -sf "$link" | grep -q "Email verified" || die "magic link click"
  # Holder proof-of-possession: sign the issuer's holder_proof_message (an
  # issuer that predates it returns none, and we issue without a proof).
  proof=$(json "$WORK/sess.json" 'd.get("holder_proof_message","")')
  [[ -z "$proof" ]] || proof=$(sign_b64 "$WORK/$name.pem" "$proof")
  curl -sf -X POST "$ISSUER/v1/credentials/issue" -H 'Content-Type: application/json' \
    -d "{\"session_id\":\"$session\",\"holder_proof_b64\":\"$proof\"}" >"$WORK/issue.json" || die "credentials/issue"
  python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["credential"], open(sys.argv[2],"w"))' "$WORK/issue.json" "$WORK/$name.json"
  echo "credential $(json "$WORK/$name.json" 'd["id"]') for $(json "$WORK/$name.json" 'd["credentialSubject"]["id"]')"
}

commitment() { json "$1" '(d["credentialSubject"].get("nullifierBinding") or {}).get("commitment","")'; }

post_claim() { # $1 = body file; prints HTTP status, body to $WORK/claim.out
  curl -s -o "$WORK/claim.out" -w '%{http_code}' -X POST "$OPENLINE/commons/claim" \
    -H 'Content-Type: application/json' --data-binary @"$1"
}

# claim CREDFILE PEMFILE: presents the credential over a fresh challenge.
claim() {
  local ch dom sig
  curl -sf -X POST "$OPENLINE/personhood/challenge" -H 'Content-Type: application/json' -d '{}' >"$WORK/challenge.json" \
    || die "POST /personhood/challenge"
  ch=$(json "$WORK/challenge.json" 'd["challenge"]')
  dom=$(json "$WORK/challenge.json" 'd["domain"]')
  sig=$(sign "$2" "$ch|$dom")
  python3 -c 'import json,sys; print(json.dumps({"address":sys.argv[2],"presentation":{"credential":json.load(open(sys.argv[1])),"challenge":sys.argv[3],"domain":sys.argv[4],"holderSig":sys.argv[5]}}))' \
    "$1" "$SELF" "$ch" "$dom" "$sig" >"$WORK/claim.json"
  post_claim "$WORK/claim.json"
}

# claim_raw CREDFILE: the bare credential, no presentation.
claim_raw() {
  python3 -c 'import json,sys; print(json.dumps({"address":sys.argv[2],"credential":json.load(open(sys.argv[1]))}))' "$1" "$SELF" >"$WORK/claim.json"
  post_claim "$WORK/claim.json"
}

EMAIL="e2e-openline-$(date +%s)@example.com"
step "fresh credential from the live issuer"
enroll "$EMAIL" cred

step "tampered credential, validly presented, is refused"
python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); c["expirationDate"]="2099-01-01T00:00:00Z"; json.dump(c,open(sys.argv[2],"w"))' "$WORK/cred.json" "$WORK/tampered.json"
CODE=$(claim "$WORK/tampered.json" "$WORK/cred.pem")
case "$CODE" in
  2*|409) die "tampered credential got HTTP $CODE: $(cat "$WORK/claim.out")" ;;
  *) echo "refused with HTTP $CODE: $(head -c 200 "$WORK/claim.out")" ;;
esac

if [[ "$DEDUP" == "True" ]]; then
  step "same email, new holder key: same nullifierBinding"
  enroll "$EMAIL" again
  C1=$(commitment "$WORK/cred.json"); C2=$(commitment "$WORK/again.json")
  [[ -n "$C1" ]] || die "credential has no nullifierBinding"
  [[ "$C1" == "$C2" ]] || die "re-enrolling $EMAIL gave a different commitment ($C1 vs $C2): one inbox is minting independent credentials"
  echo "re-issue kept commitment ${C1:0:16}…"
else
  echo "WARN: issuer reports identifier_dedup=false; one inbox can mint unlimited credentials (set IDENTIFIER_HMAC_KEY)"
fi

if [[ "${OPENLINE_E2E_CLAIM:-}" == "1" ]]; then
  step "OPENLINE_E2E_CLAIM=1: raw credential refused, real claim, then duplicates"
  CODE=$(claim_raw "$WORK/cred.json")
  [[ "$CODE" == 403 ]] || die "raw credential (no presentation) got HTTP $CODE, want 403: $(cat "$WORK/claim.out")"
  echo "raw credential refused (403)"
  CODE=$(claim "$WORK/cred.json" "$WORK/cred.pem")
  [[ "$CODE" == 200 ]] || die "claim got HTTP $CODE: $(cat "$WORK/claim.out")"
  echo "claimed: $(head -c 200 "$WORK/claim.out")"
  CODE=$(claim "$WORK/cred.json" "$WORK/cred.pem")
  [[ "$CODE" == 409 ]] || die "duplicate claim got HTTP $CODE, want 409: $(cat "$WORK/claim.out")"
  echo "duplicate refused (409)"
  if [[ "$DEDUP" == "True" ]]; then
    CODE=$(claim "$WORK/again.json" "$WORK/again.pem")
    [[ "$CODE" == 409 ]] || die "re-enrolled credential for the same email got HTTP $CODE, want 409: $(cat "$WORK/claim.out")"
    echo "same email under a new holder key refused as the same person (409)"
  fi
else
  echo "(skipping the ledger-mutating claim; set OPENLINE_E2E_CLAIM=1 to run it)"
fi

echo
echo "e2e-openline PASSED"
