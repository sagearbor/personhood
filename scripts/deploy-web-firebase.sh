#!/usr/bin/env bash
# scripts/deploy-web-firebase.sh — build the static Next.js export of app/web
# and deploy it to Firebase Hosting.
#
# Usage:
#   NEXT_PUBLIC_PERSONHOOD_SERVER_URL=https://personhood-issuer-....run.app \
#     bash scripts/deploy-web-firebase.sh
#
#   -h / --help   print this usage and exit 0 without touching anything.
#
# Required (env, or positional $1 -- env preferred):
#   NEXT_PUBLIC_PERSONHOOD_SERVER_URL   the deployed issuer URL; baked into the static
#                                       export at build time (Next.js NEXT_PUBLIC_* vars
#                                       are compile-time, not runtime).
#
# Optional:
#   PROJECT   firebase/gcloud project id to deploy to; default: whatever .firebaserc's
#             "default" project is (see --project flag semantics of the firebase CLI).
#   WEB_URL   URL to curl-check after deploy; default: https://personhood-web.web.app
#
# What this does:
#   1. cd app/web && NEXT_PUBLIC_PERSONHOOD_SERVER_URL=... npm run build
#      (Next.js "output: export" produces app/web/out/)
#   2. firebase deploy --only hosting:web [--project $PROJECT]
#   3. curl-check / and /manifest.webmanifest on $WEB_URL
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: NEXT_PUBLIC_PERSONHOOD_SERVER_URL=<issuer-url> bash scripts/deploy-web-firebase.sh [issuer_url] [project]

Required env (or positional $1):
  NEXT_PUBLIC_PERSONHOOD_SERVER_URL   deployed issuer URL, baked in at build time

Optional env:
  PROJECT   firebase/gcloud project id (default: .firebaserc's default project)
  WEB_URL   URL to smoke-test after deploy (default: https://personhood-web.web.app)

This script builds app/web and runs `firebase deploy` -- it changes the live Hosting
site. Re-running it is safe (it always redeploys the freshly built export) but it is not
a dry run.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SERVER_URL="${NEXT_PUBLIC_PERSONHOOD_SERVER_URL:-${1:-}}"
PROJECT="${PROJECT:-${2:-}}"
WEB_URL="${WEB_URL:-https://personhood-web.web.app}"

if [[ -z "$SERVER_URL" ]]; then
  echo "error: NEXT_PUBLIC_PERSONHOOD_SERVER_URL is required." >&2
  usage >&2
  exit 1
fi

command -v firebase >/dev/null 2>&1 || { echo "error: firebase CLI not found (npm i -g firebase-tools)." >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "error: npm not found." >&2; exit 1; }

cd "$(dirname "$0")/.."
ROOT="$PWD"

echo "==> building static export (app/web) against $SERVER_URL"
(cd "$ROOT/app/web" && NEXT_PUBLIC_PERSONHOOD_SERVER_URL="$SERVER_URL" npm run build)

[[ -d "$ROOT/app/web/out" ]] || { echo "error: app/web/out was not produced by the build." >&2; exit 1; }

DEPLOY_ARGS=(deploy --only hosting:web)
[[ -n "$PROJECT" ]] && DEPLOY_ARGS+=(--project "$PROJECT")

echo "==> firebase ${DEPLOY_ARGS[*]}"
(cd "$ROOT" && firebase "${DEPLOY_ARGS[@]}")

echo "==> smoke-testing $WEB_URL"
if curl -sf -o /dev/null "$WEB_URL/"; then
  echo "    / ok"
else
  echo "    / FAILED"
  exit 1
fi

if curl -sf "$WEB_URL/manifest.webmanifest" >/dev/null; then
  echo "    /manifest.webmanifest ok"
else
  echo "    /manifest.webmanifest FAILED"
  exit 1
fi

echo
echo "deployed: $WEB_URL"
