#!/usr/bin/env bash
# scripts/deploy-cloudrun.sh — deploy (or redeploy) the Personhood issuer to
# Google Cloud Run from source, idempotently.
#
# Usage:
#   PROJECT=arborfam-hub WEB_ORIGIN=https://personhood-web.web.app \
#     bash scripts/deploy-cloudrun.sh
#
#   -h / --help   print this usage and exit 0 without touching anything.
#
# Required (env, or positional $1/$2 -- prefer env so secrets never land in
# shell history or `ps`):
#   PROJECT       GCP project id
#   WEB_ORIGIN    origin(s) allowed by CORS, comma-separated, e.g.
#                 https://personhood-web.web.app,https://openline-wallet.web.app
#
# Optional (env only):
#   REGION                          default: us-central1
#   SERVICE                         default: personhood-issuer
#   SECRET_NAME                     default: personhood-issuer-key
#   INVITE_CODE                     sets ENROLLMENT_INVITE_CODE; omit for no invite gate.
#                                   NEVER pass this as a CLI argument.
#   DEV_EXPOSE_CHALLENGE_SECRETS    default: 1 (test mode -- magic link comes back in the
#                                   API response, for a deployment with no email provider
#                                   wired). Set to 0 once SMTP is configured (see RUNBOOK.md).
#   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_FROM   passed through as plain env vars when
#                                   SMTP_HOST and SMTP_FROM are both set. SMTP_PASS is
#                                   deliberately NOT forwarded by this script -- store it in
#                                   Secret Manager and wire it with --set-secrets by hand
#                                   (see RUNBOOK.md, "turn test mode off").
#   FIRESTORE_PROJECT_ID            when set, enables the Firestore-backed SessionStore /
#                                   email.TokenStore / sms.OTPStore / government-id-liveness
#                                   ResultStore (pkg/firestoreclient) instead of the in-memory
#                                   defaults, so state survives restarts and new revisions.
#                                   Usually just PROJECT itself (they share one GCP project's
#                                   free-tier Firestore Native "(default)" database). Enables
#                                   firestore.googleapis.com and grants the compute service
#                                   account roles/datastore.user. Falls back to REDIS_URL
#                                   (unaffected by this script) or in-memory if unset.
#
# What this does, in order, and why it is safe to re-run:
#   1. gcloud config set project
#   2. enable secretmanager / run / cloudbuild APIs (no-op if already on); also
#      firestore.googleapis.com when FIRESTORE_PROJECT_ID is set
#   3. create the issuer-key secret from `gen-key` ONLY if it does not already
#      exist. It NEVER overwrites an existing key -- rotating it invalidates
#      every credential issued so far -- and instead prints the command to
#      read the existing key for a backup.
#   4. grant the default compute service account secretAccessor on it, and
#      (when FIRESTORE_PROJECT_ID is set) roles/datastore.user on the project
#      (idempotent: add-iam-policy-binding is a no-op if already granted)
#   5. gcloud run deploy --source .
#   6. smoke-test /health, /v1/methods, /.well-known/did.json and print the
#      issuer DID + public key.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: PROJECT=<gcp-project> WEB_ORIGIN=<https://your-web-origin> bash scripts/deploy-cloudrun.sh [project] [web_origin]

Required env (or positional args -- env preferred so secrets never hit shell history):
  PROJECT            GCP project id
  WEB_ORIGIN         Origin(s) allowed by CORS, comma-separated, e.g.
                     https://personhood-web.web.app,https://openline-wallet.web.app

Optional env:
  REGION                          default: us-central1
  SERVICE                         default: personhood-issuer
  SECRET_NAME                     default: personhood-issuer-key
  INVITE_CODE                     sets ENROLLMENT_INVITE_CODE (never pass as a CLI arg)
  DEV_EXPOSE_CHALLENGE_SECRETS    default: 1 (test mode). Set to 0 once SMTP is configured.
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_FROM   optional real email delivery config.
                                   SMTP_PASS is never forwarded by this script.
  FIRESTORE_PROJECT_ID             when set, enables the Firestore-backed stores instead of
                                   in-memory (falls back to REDIS_URL, then in-memory).

This script mutates the live Cloud Run service. Re-running it is safe (idempotent) but it
DOES deploy a new revision every time -- it is not a dry run.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

PROJECT="${PROJECT:-${1:-}}"
WEB_ORIGIN="${WEB_ORIGIN:-${2:-}}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-personhood-issuer}"
SECRET_NAME="${SECRET_NAME:-personhood-issuer-key}"
DEV_EXPOSE_CHALLENGE_SECRETS="${DEV_EXPOSE_CHALLENGE_SECRETS:-1}"

if [[ -z "$PROJECT" || -z "$WEB_ORIGIN" ]]; then
  echo "error: PROJECT and WEB_ORIGIN are required." >&2
  usage >&2
  exit 1
fi

command -v gcloud >/dev/null 2>&1 || { echo "error: gcloud CLI not found." >&2; exit 1; }

cd "$(dirname "$0")/.."

echo "==> gcloud config set project $PROJECT"
gcloud config set project "$PROJECT" >/dev/null

echo "==> enabling APIs (no-op if already on)"
APIS="secretmanager.googleapis.com run.googleapis.com cloudbuild.googleapis.com"
[[ -n "${FIRESTORE_PROJECT_ID:-}" ]] && APIS="$APIS firestore.googleapis.com"
gcloud services enable $APIS --project "$PROJECT"

PROJECT_NUMBER=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')
[[ -n "$PROJECT_NUMBER" ]] || { echo "error: could not resolve project number for $PROJECT" >&2; exit 1; }
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
SERVER_PUBLIC_URL="https://${SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"

echo "==> issuer key secret: $SECRET_NAME"
if gcloud secrets describe "$SECRET_NAME" --project "$PROJECT" >/dev/null 2>&1; then
  echo "    already exists -- leaving it untouched."
  echo "    (rotating it invalidates every credential issued so far)"
  echo "    backup command: gcloud secrets versions access latest --secret=$SECRET_NAME --project $PROJECT"
else
  echo "    not found -- generating a new key with gen-key and creating the secret (version 1)"
  command -v go >/dev/null 2>&1 || { echo "error: go toolchain not found; needed to run gen-key." >&2; exit 1; }
  KEY_LINE=$(go run ./src/server/cmd/gen-key 2>/dev/null | grep '^ISSUER_ED25519_SK_B64=')
  KEY_VALUE="${KEY_LINE#ISSUER_ED25519_SK_B64=}"
  [[ -n "$KEY_VALUE" ]] || { echo "error: gen-key produced no key." >&2; exit 1; }
  printf '%s' "$KEY_VALUE" | gcloud secrets create "$SECRET_NAME" --data-file=- --project "$PROJECT"
  unset KEY_LINE KEY_VALUE
  echo "    created. BACK IT UP NOW (e.g. into a password manager):"
  echo "      gcloud secrets versions access latest --secret=$SECRET_NAME --project $PROJECT"
fi

echo "==> granting roles/secretmanager.secretAccessor to $COMPUTE_SA"
gcloud secrets add-iam-policy-binding "$SECRET_NAME" \
  --project "$PROJECT" \
  --member="serviceAccount:${COMPUTE_SA}" \
  --role="roles/secretmanager.secretAccessor" >/dev/null

if [[ -n "${FIRESTORE_PROJECT_ID:-}" ]]; then
  echo "==> granting roles/datastore.user to $COMPUTE_SA (Firestore project $FIRESTORE_PROJECT_ID)"
  gcloud projects add-iam-policy-binding "$FIRESTORE_PROJECT_ID" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/datastore.user" >/dev/null
fi

# TRUSTED_PROXY_HOPS=1: Cloud Run's frontend appends the real client IP to
# X-Forwarded-For, so the issuer's rate limiter keys on the rightmost entry.
#
# Entries are joined with "@" and passed with gcloud's "^@^" delimiter prefix,
# because CORS_ALLOWED_ORIGINS is itself a comma-separated list (WEB_ORIGIN
# may name several origins, e.g. the web app and the OpenLine wallet).
ENV_VARS="SERVER_PUBLIC_URL=${SERVER_PUBLIC_URL}@CORS_ALLOWED_ORIGINS=${WEB_ORIGIN}@TRUSTED_PROXY_HOPS=1"
if [[ -n "$DEV_EXPOSE_CHALLENGE_SECRETS" && "$DEV_EXPOSE_CHALLENGE_SECRETS" != "0" ]]; then
  ENV_VARS="${ENV_VARS}@DEV_EXPOSE_CHALLENGE_SECRETS=${DEV_EXPOSE_CHALLENGE_SECRETS}"
fi
if [[ -n "${INVITE_CODE:-}" ]]; then
  ENV_VARS="${ENV_VARS}@ENROLLMENT_INVITE_CODE=${INVITE_CODE}"
fi
if [[ -n "${SMTP_HOST:-}" && -n "${SMTP_FROM:-}" ]]; then
  ENV_VARS="${ENV_VARS}@SMTP_HOST=${SMTP_HOST}@SMTP_FROM=${SMTP_FROM}"
  [[ -n "${SMTP_PORT:-}" ]] && ENV_VARS="${ENV_VARS}@SMTP_PORT=${SMTP_PORT}"
  [[ -n "${SMTP_USER:-}" ]] && ENV_VARS="${ENV_VARS}@SMTP_USER=${SMTP_USER}"
  if [[ -n "${SMTP_PASS:-}" ]]; then
    echo "warn: SMTP_PASS is set but this script does not forward it as a plain env var." >&2
    echo "      store it in Secret Manager and attach it with --set-secrets by hand; see" >&2
    echo "      RUNBOOK.md's Google Cloud section, 'turn test mode off'." >&2
  fi
fi
if [[ -n "${FIRESTORE_PROJECT_ID:-}" ]]; then
  ENV_VARS="${ENV_VARS}@FIRESTORE_PROJECT_ID=${FIRESTORE_PROJECT_ID}"
fi


# --set-env-vars REPLACES the service's whole env. Refuse a deploy that would
# silently drop a variable or a CORS origin the live service has today (a
# forgotten INVITE_CODE turns the invite gate off; a single WEB_ORIGIN drops
# every other allowed origin). Names only are compared/printed, never values.
# ALLOW_ENV_DROP=1 overrides when the drop is intended.
LIVE_ENV_JSON=$(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format=json 2>/dev/null || true)
if [[ -n "$LIVE_ENV_JSON" ]]; then
  DROPS=$(NEW_ENV="$ENV_VARS" python3 -c '
import json, os, sys
live = json.load(sys.stdin)["spec"]["template"]["spec"]["containers"][0].get("env", [])
new = dict(kv.split("=", 1) for kv in os.environ["NEW_ENV"].split("@"))
drops = [e["name"] for e in live if "value" in e and e["name"] not in new]
for e in live:
    if e["name"] == "CORS_ALLOWED_ORIGINS" and "value" in e:
        keep = {o.strip() for o in new.get("CORS_ALLOWED_ORIGINS", "").split(",")}
        drops += ["CORS origin " + o.strip() for o in e["value"].split(",") if o.strip() and o.strip() not in keep]
print("\n".join(drops))
' <<<"$LIVE_ENV_JSON")
  if [[ -n "$DROPS" && "${ALLOW_ENV_DROP:-}" != "1" ]]; then
    echo "error: this deploy would remove settings the live $SERVICE has:" >&2
    sed 's/^/  - /' <<<"$DROPS" >&2
    echo "pass them again (WEB_ORIGIN takes a comma-separated list), or set ALLOW_ENV_DROP=1 if intended." >&2
    exit 1
  fi
fi

# Optional admin token for POST /v1/admin/revoke. Attached only when the
# secret exists; create it once with
#   openssl rand -base64 32 | tr -d '\n' | gcloud secrets create personhood-admin-token --data-file=- --project $PROJECT
# (--set-secrets replaces the whole secret set, so both are always passed).
ADMIN_SECRET_NAME="${ADMIN_SECRET_NAME:-personhood-admin-token}"
SECRETS="ISSUER_ED25519_SK_B64=${SECRET_NAME}:latest"
if gcloud secrets describe "$ADMIN_SECRET_NAME" --project "$PROJECT" >/dev/null 2>&1; then
  gcloud secrets add-iam-policy-binding "$ADMIN_SECRET_NAME" \
    --project "$PROJECT" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" >/dev/null
  SECRETS="${SECRETS},ADMIN_TOKEN=${ADMIN_SECRET_NAME}:latest"
  echo "==> admin token: attaching secret $ADMIN_SECRET_NAME (POST /v1/admin/revoke on)"
else
  echo "==> admin token: no secret $ADMIN_SECRET_NAME, admin routes stay off"
fi

echo "==> deploying $SERVICE to $REGION (source build)"
gcloud run deploy "$SERVICE" \
  --project "$PROJECT" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --memory 256Mi \
  --max-instances 1 \
  --set-secrets "$SECRETS" \
  --set-env-vars "^@^${ENV_VARS}"

echo "==> smoke-testing $SERVER_PUBLIC_URL"
if curl -sf "${SERVER_PUBLIC_URL}/health" | grep -q '"ok"'; then
  echo "    /health ok"
else
  echo "    /health FAILED (note: /healthz is intercepted by Cloud Run's frontend -- use /health)"
  exit 1
fi

if curl -sf "${SERVER_PUBLIC_URL}/v1/methods" >/dev/null; then
  echo "    /v1/methods ok"
else
  echo "    /v1/methods FAILED"
  exit 1
fi

DID_JSON=$(curl -sf "${SERVER_PUBLIC_URL}/.well-known/did.json") \
  || { echo "    /.well-known/did.json FAILED"; exit 1; }
echo "    /.well-known/did.json ok"

echo
echo "== deployed =="
echo "issuer URL: $SERVER_PUBLIC_URL"
if command -v python3 >/dev/null 2>&1; then
  python3 -c '
import json, sys
d = json.loads(sys.argv[1])
print("DID:", d.get("id"))
vm = d.get("verificationMethod") or [{}]
print("public key x:", vm[0].get("publicKeyJwk", {}).get("x"))
' "$DID_JSON"
else
  echo "did.json: $DID_JSON"
fi
