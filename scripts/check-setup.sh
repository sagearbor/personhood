#!/usr/bin/env bash
# tmp/check-setup.sh — one-shot verification of every credential the
# Personhood demo needs. Run from the repo root:
#
#   bash tmp/check-setup.sh
#
# Loads `.env.local` if present and then hits a no-side-effect API on each
# vendor to confirm the key actually works. Prints OK / SKIP / FAIL for each
# section so you can tell at a glance what is left to set up.
#
# Nothing here sends an email, sends an SMS, or creates a Persona inquiry.
# Each call is a metadata read.

set -u

# ----- formatting helpers ---------------------------------------------------

if [ -t 1 ]; then
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; X=$'\e[0m'
else
  G=""; R=""; Y=""; B=""; D=""; X=""
fi

ok()    { printf "  ${G}✓${X} %s\n" "$1"; }
fail()  { printf "  ${R}✗${X} %s\n" "$1"; }
skip()  { printf "  ${Y}-${X} %s\n" "$1"; }
note()  { printf "    ${D}%s${X}\n" "$1"; }
section() { printf "\n${B}%s${X}\n" "$1"; }

# ----- load .env.local ------------------------------------------------------

if [ -f .env.local ]; then
  set -a
  # shellcheck disable=SC1091
  source .env.local
  set +a
  printf "${G}Loaded .env.local${X}\n"
else
  printf "${Y}No .env.local found — every section will SKIP. Copy from .example.env:\n  cp .example.env .env.local${X}\n"
fi

# ----- 1. SendGrid ----------------------------------------------------------

section "1. SendGrid (email magic link)"
if [ -z "${SENDGRID_API_KEY:-}" ]; then
  skip "SENDGRID_API_KEY not set"
  note "Sign up: https://signup.sendgrid.com/   (free 100 emails/day forever)"
  note "Key:     https://app.sendgrid.com/settings/api_keys"
else
  code=$(curl -sS -o /tmp/sg.json -w '%{http_code}' \
    -H "Authorization: Bearer ${SENDGRID_API_KEY}" \
    https://api.sendgrid.com/v3/scopes 2>/dev/null || echo "000")
  if [ "$code" = "200" ]; then
    ok "API key valid (GET /v3/scopes returned 200)"
    if command -v jq >/dev/null 2>&1; then
      count=$(jq '.scopes | length' /tmp/sg.json 2>/dev/null || echo "?")
      note "Key has $count scopes."
    fi
  elif [ "$code" = "401" ]; then
    fail "API key rejected (401 unauthorized)"
    note "Generate a new key at https://app.sendgrid.com/settings/api_keys"
  elif [ "$code" = "000" ]; then
    fail "Cannot reach api.sendgrid.com — check your network."
  else
    fail "Unexpected HTTP $code from SendGrid"
    note "Body excerpt:"
    head -c 240 /tmp/sg.json 2>/dev/null; echo
  fi

  # Check verified sender
  if [ -n "${SENDGRID_FROM:-}" ] && [ "$code" = "200" ]; then
    sender_code=$(curl -sS -o /tmp/sg_senders.json -w '%{http_code}' \
      -H "Authorization: Bearer ${SENDGRID_API_KEY}" \
      https://api.sendgrid.com/v3/verified_senders 2>/dev/null || echo "000")
    if [ "$sender_code" = "200" ] && command -v jq >/dev/null 2>&1; then
      if jq -e --arg e "$SENDGRID_FROM" '.results[]? | select(.from_email == $e and .verified.status == true)' /tmp/sg_senders.json >/dev/null 2>&1; then
        ok "Sender '${SENDGRID_FROM}' is verified"
      else
        fail "Sender '${SENDGRID_FROM}' is not in the verified-senders list"
        note "Verify it at https://app.sendgrid.com/settings/sender_auth/senders"
      fi
    fi
  fi
fi

# ----- 2. Twilio ------------------------------------------------------------

section "2. Twilio (SMS OTP)"
if [ -z "${TWILIO_ACCOUNT_SID:-}" ] || [ -z "${TWILIO_AUTH_TOKEN:-}" ]; then
  skip "TWILIO_ACCOUNT_SID and/or TWILIO_AUTH_TOKEN not set"
  note "Sign up: https://www.twilio.com/try-twilio   (~\$15 trial credit + free trial number)"
  note "Console: https://console.twilio.com/   (Account SID + Auth Token on the home page)"
else
  code=$(curl -sS -o /tmp/tw.json -w '%{http_code}' \
    -u "${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}" \
    "https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}.json" 2>/dev/null || echo "000")
  if [ "$code" = "200" ]; then
    ok "Twilio credentials valid (account exists, auth OK)"
    if command -v jq >/dev/null 2>&1; then
      status=$(jq -r .status /tmp/tw.json 2>/dev/null)
      friendly=$(jq -r .friendly_name /tmp/tw.json 2>/dev/null)
      note "Account: ${friendly} (status: ${status})"
    fi
    if [ -n "${TWILIO_FROM:-}" ]; then
      # Confirm From number is on this account.
      from_code=$(curl -sS -o /tmp/tw_nums.json -w '%{http_code}' \
        -u "${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}" \
        "https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/IncomingPhoneNumbers.json?PhoneNumber=${TWILIO_FROM}" 2>/dev/null || echo "000")
      if [ "$from_code" = "200" ] && command -v jq >/dev/null 2>&1; then
        if [ "$(jq '.incoming_phone_numbers | length' /tmp/tw_nums.json)" -gt 0 ]; then
          ok "TWILIO_FROM=${TWILIO_FROM} is owned by this account"
        else
          fail "TWILIO_FROM=${TWILIO_FROM} is NOT in this account's number list"
          note "Get one at https://console.twilio.com/us1/develop/phone-numbers/manage/incoming"
        fi
      fi
    else
      note "TWILIO_FROM not set; sending will fail until you add it."
    fi
  elif [ "$code" = "401" ]; then
    fail "Twilio rejected the SID + auth token (401)"
    note "Copy fresh values from https://console.twilio.com/"
  elif [ "$code" = "000" ]; then
    fail "Cannot reach api.twilio.com — check your network."
  else
    fail "Unexpected HTTP $code from Twilio"
    head -c 240 /tmp/tw.json 2>/dev/null; echo
  fi
fi

# ----- 3. Persona -----------------------------------------------------------

section "3. Persona (government ID + selfie anchor)"
if [ -z "${PERSONA_API_KEY:-}" ]; then
  skip "PERSONA_API_KEY not set"
  note "Sign up: https://withpersona.com/   (sandbox is free, no credit card)"
  note "Keys:    https://withpersona.com/dashboard/api-keys"
else
  code=$(curl -sS -o /tmp/persona.json -w '%{http_code}' \
    -H "Authorization: Bearer ${PERSONA_API_KEY}" \
    -H "Persona-Version: 2023-01-05" \
    "https://withpersona.com/api/v1/inquiries?page%5Bsize%5D=1" 2>/dev/null || echo "000")
  if [ "$code" = "200" ]; then
    ok "Persona API key valid (GET /api/v1/inquiries returned 200)"
    if [[ "$PERSONA_API_KEY" == persona_sandbox_* ]]; then
      note "Sandbox key — free, fine for the demo."
    elif [[ "$PERSONA_API_KEY" == persona_production_* ]]; then
      note "Production key — billed per inquiry (~\$2)."
    fi
  elif [ "$code" = "401" ]; then
    fail "Persona rejected the key (401 unauthorized)"
    note "Generate a new sandbox key at https://withpersona.com/dashboard/api-keys"
  elif [ "$code" = "000" ]; then
    fail "Cannot reach withpersona.com — check your network."
  else
    fail "Unexpected HTTP $code from Persona"
    head -c 240 /tmp/persona.json 2>/dev/null; echo
  fi

  if [ -n "${PERSONA_TEMPLATE_ID:-}" ] && [ "$code" = "200" ]; then
    tpl_code=$(curl -sS -o /tmp/persona_tpl.json -w '%{http_code}' \
      -H "Authorization: Bearer ${PERSONA_API_KEY}" \
      -H "Persona-Version: 2023-01-05" \
      "https://withpersona.com/api/v1/inquiry-templates/${PERSONA_TEMPLATE_ID}" 2>/dev/null || echo "000")
    if [ "$tpl_code" = "200" ]; then
      ok "Template '${PERSONA_TEMPLATE_ID}' exists"
    else
      fail "Template '${PERSONA_TEMPLATE_ID}' returned HTTP $tpl_code"
      note "Create one at https://withpersona.com/dashboard/inquiry-templates"
    fi
  else
    note "PERSONA_TEMPLATE_ID not set; ceremonies will fail until you add it."
  fi

  if [ -z "${PERSONA_WEBHOOK_SECRET:-}" ]; then
    note "PERSONA_WEBHOOK_SECRET not set yet. The server only registers the gov-id"
    note "method when this is present. Set it after creating the webhook in"
    note "https://withpersona.com/dashboard/webhooks (Persona shows it once)."
  else
    ok "PERSONA_WEBHOOK_SECRET is set"
  fi
fi

# ----- 4. Fly.io ------------------------------------------------------------

section "4. Fly.io (server host)"
if ! command -v fly >/dev/null 2>&1; then
  skip "fly CLI not installed"
  note "Install: brew install flyctl   (macOS)"
  note "         curl -L https://fly.io/install.sh | sh   (Linux)"
else
  if fly auth whoami >/tmp/fly.txt 2>&1; then
    ok "Logged in as $(cat /tmp/fly.txt | head -1)"
  else
    skip "Not signed in to Fly.io"
    note "Run: fly auth signup   (free tier: 3 shared-cpu-1x VMs, no card)"
  fi
fi

# ----- 5. Vercel ------------------------------------------------------------

section "5. Vercel (web host)"
if ! command -v vercel >/dev/null 2>&1; then
  skip "vercel CLI not installed"
  note "Install: npm i -g vercel"
else
  if vercel whoami >/tmp/vercel.txt 2>&1; then
    ok "Logged in as $(cat /tmp/vercel.txt | head -1)"
  else
    skip "Not signed in to Vercel"
    note "Run: vercel login   (free Hobby tier)"
  fi
fi

# ----- 6. GitHub ------------------------------------------------------------

section "6. GitHub (gh CLI for PR ops)"
if ! command -v gh >/dev/null 2>&1; then
  skip "gh CLI not installed"
  note "Install: brew install gh   then  gh auth login"
else
  if gh auth status >/tmp/gh.txt 2>&1; then
    ok "gh is authenticated"
    grep -E "Logged in to" /tmp/gh.txt | sed 's/^/    /'
  else
    fail "gh is not authenticated"
    note "Run: gh auth login"
  fi
fi

# ----- 7. Issuer signing key -----------------------------------------------

section "7. Issuer signing key"
if [ -z "${ISSUER_ED25519_SK_B64:-}" ]; then
  skip "ISSUER_ED25519_SK_B64 not set"
  note "Generate: go run ./src/server/cmd/gen-key   (copies a one-line export)"
else
  if [ ${#ISSUER_ED25519_SK_B64} -ge 40 ]; then
    ok "ISSUER_ED25519_SK_B64 is set (${#ISSUER_ED25519_SK_B64} characters)"
  else
    fail "ISSUER_ED25519_SK_B64 looks too short (${#ISSUER_ED25519_SK_B64} chars)"
    note "Regenerate with: go run ./src/server/cmd/gen-key"
  fi
fi

# ----- Summary -------------------------------------------------------------

printf "\n${B}Done.${X} Counts:\n"
printf "  Look above for any ${R}✗${X} (must fix before deploy) or ${Y}-${X} (still to do).\n"
printf "  When everything shows ${G}✓${X}, run section 5 of RUNBOOK.md to deploy.\n"
