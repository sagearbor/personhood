#!/usr/bin/env bash
# tmp/test-sendgrid.sh — verify the SendGrid API key works without sending mail.
# Run from repo root: `bash tmp/test-sendgrid.sh`
# Requires .env.local with SENDGRID_API_KEY set.

set -euo pipefail

if [ -f .env.local ]; then
  set -a
  # shellcheck disable=SC1091
  source .env.local
  set +a
elif [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [ -z "${SENDGRID_API_KEY:-}" ]; then
  echo "ERROR: SENDGRID_API_KEY is not set. Add it to .env.local (see .env.example)." >&2
  exit 1
fi

echo "==> 1. Checking API key scopes..."
http_code=$(curl -sS -o /tmp/sg_scopes.json -w '%{http_code}' \
  -H "Authorization: Bearer ${SENDGRID_API_KEY}" \
  https://api.sendgrid.com/v3/scopes)

if [ "$http_code" != "200" ]; then
  echo "FAIL: /v3/scopes returned HTTP $http_code"
  cat /tmp/sg_scopes.json
  exit 1
fi

echo "OK. Key has these scopes (first 20):"
if command -v jq >/dev/null 2>&1; then
  jq '.scopes[0:20]' /tmp/sg_scopes.json
else
  head -c 1000 /tmp/sg_scopes.json
  echo
fi

echo
echo "==> 2. Listing verified senders..."
http_code=$(curl -sS -o /tmp/sg_senders.json -w '%{http_code}' \
  -H "Authorization: Bearer ${SENDGRID_API_KEY}" \
  https://api.sendgrid.com/v3/verified_senders)

if [ "$http_code" != "200" ]; then
  echo "WARN: /v3/verified_senders returned HTTP $http_code (key may lack 'sender_verification_eligible' scope)"
else
  if command -v jq >/dev/null 2>&1; then
    jq '.results | map({email: .from_email, verified: .verified.status})' /tmp/sg_senders.json
  else
    head -c 1000 /tmp/sg_senders.json
    echo
  fi
fi

echo
echo "==> 3. Listing authenticated domains..."
http_code=$(curl -sS -o /tmp/sg_domains.json -w '%{http_code}' \
  -H "Authorization: Bearer ${SENDGRID_API_KEY}" \
  https://api.sendgrid.com/v3/whitelabel/domains)
if [ "$http_code" = "200" ]; then
  if command -v jq >/dev/null 2>&1; then
    jq 'map({domain, valid})' /tmp/sg_domains.json
  else
    head -c 500 /tmp/sg_domains.json
    echo
  fi
else
  echo "(skipped, HTTP $http_code)"
fi

echo
echo "All checks finished. If you saw an OK on step 1 and at least one verified sender or domain on step 2/3, SendGrid is ready."
