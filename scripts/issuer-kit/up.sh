#!/usr/bin/env bash
# scripts/issuer-kit/up.sh — start (or update) an independent Personhood issuer.
#
#   ./up.sh --domain issuer.example.org   HTTPS on your own domain (A record -> this box)
#   ./up.sh --sslip                       HTTPS on <your-ip>.sslip.io, no domain needed
#   ./up.sh --local                       http://127.0.0.1:8090, no HTTPS (trying it out)
#
# Extra flags:
#   --test-mode      rehearsal: sign-in links are shown on screen instead of
#                    emailed, so anyone can enroll any address. Not for real use.
#   --port N         loopback port for the issuer (default 8090)
#
# The first run writes issuer.env (mode 0600) with a fresh signing key, the
# one-inbox-one-voter key and an admin token. Later runs keep those keys and
# only update SERVER_PUBLIC_URL, TRUSTED_PROXY_HOPS and the test-mode flag.
# Nothing secret is printed. When the issuer is up, this prints its DID and
# public key: that is what an integrator (OpenLine) pins.
#
# Needs: docker with the compose plugin, curl, openssl. See docs/RUN_AN_ISSUER.md.
set -euo pipefail

cd "$(dirname "$0")"
ENV_FILE=issuer.env
MODE=""
DOMAIN=""
TEST_MODE=""
PORT=8090

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die() { printf 'up.sh: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) MODE=domain; DOMAIN="${2:-}"; shift 2 ;;
    --sslip) MODE=sslip; shift ;;
    --local) MODE=local; shift ;;
    --test-mode) TEST_MODE=1; shift ;;
    --port) PORT="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) usage 1 ;;
  esac
done
[ -n "$MODE" ] || usage 1
case "$PORT" in ''|*[!0-9]*) die "--port needs a number" ;; esac
command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed"
command -v openssl >/dev/null || die "openssl is not installed"

case "$MODE" in
  domain)
    [ -n "$DOMAIN" ] || die "--domain needs a name, e.g. --domain issuer.example.org"
    case "$DOMAIN" in *[!A-Za-z0-9.-]*) die "--domain: letters, digits, dots and dashes only" ;; esac
    PUBLIC_URL="https://$DOMAIN" ;;
  sslip)
    IP=$(curl -fsS --max-time 10 https://api.ipify.org) || die "could not look up this machine's public IP"
    case "$IP" in *[!0-9.]*|'') die "unexpected public IP '$IP' (IPv4 only)" ;; esac
    DOMAIN="$(printf '%s' "$IP" | tr . -).sslip.io"
    PUBLIC_URL="https://$DOMAIN" ;;
  local)
    PUBLIC_URL="http://127.0.0.1:$PORT" ;;
esac

# set_var NAME VALUE — replace (or append) one line of issuer.env in place.
set_var() {
  local tmp
  tmp=$(mktemp "$ENV_FILE.XXXXXX")
  awk -v k="$1" -v v="$2" 'BEGIN{done=0} index($0, k"=")==1 {print k"="v; done=1; next} {print} END{if(!done) print k"="v}' "$ENV_FILE" >"$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}
get_var() { awk -v k="$1" 'index($0, k"=")==1 {print substr($0, length(k)+2)}' "$ENV_FILE" | tail -1; }

umask 077
if [ ! -f "$ENV_FILE" ]; then
  cp issuer.env.example "$ENV_FILE"
  echo "created $ENV_FILE (mode 0600)"
fi
chmod 600 "$ENV_FILE"

if [ -z "$(get_var ISSUER_ED25519_SK_B64)" ]; then
  set_var ISSUER_ED25519_SK_B64 "$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  echo "generated a new issuer signing key -> back up $PWD/$ENV_FILE now (docs/RUN_AN_ISSUER.md)"
fi
if [ -z "$(get_var IDENTIFIER_HMAC_KEY)" ]; then
  set_var IDENTIFIER_HMAC_KEY "$(openssl rand 32 | openssl base64 -A)"
fi
if [ -z "$(get_var ADMIN_TOKEN)" ]; then
  set_var ADMIN_TOKEN "$(openssl rand -hex 32)"
fi
set_var SERVER_PUBLIC_URL "$PUBLIC_URL"
if [ "$MODE" = local ]; then set_var TRUSTED_PROXY_HOPS 0; else set_var TRUSTED_PROXY_HOPS 1; fi
set_var DEV_EXPOSE_CHALLENGE_SECRETS "$TEST_MODE"

if [ -z "$TEST_MODE" ] && [ -z "$(get_var SMTP_HOST)" ] && [ -z "$(get_var SENDGRID_API_KEY)" ]; then
  echo "WARNING: no SMTP_* or SENDGRID_* settings in $ENV_FILE: sign-in emails are only logged, so nobody can enroll yet."
fi

export ISSUER_LOCAL_PORT="$PORT"
if [ "$MODE" = local ]; then
  docker compose up -d --build redis issuer
else
  export ISSUER_DOMAIN="$DOMAIN"
  docker compose --profile tls up -d --build
fi

LOCAL="http://127.0.0.1:$PORT"
printf 'waiting for the issuer'
for _ in $(seq 1 60); do
  curl -fsS --max-time 2 "$LOCAL/health" >/dev/null 2>&1 && break
  printf '.'; sleep 1
done
echo
curl -fsS --max-time 2 "$LOCAL/health" >/dev/null || die "the issuer did not become healthy; see: docker compose logs issuer"

DIDDOC=$(curl -fsS "$LOCAL/.well-known/did.json")
# The document's own "id" is the only one without a "#key" fragment.
DID=$(printf '%s' "$DIDDOC" | tr -d ' \n' | grep -o '"id":"did:[^"#]*"' | head -1 | cut -d'"' -f4)
X=$(printf '%s' "$DIDDOC" | tr -d ' \n' | grep -o '"x":"[^"]*"' | head -1 | cut -d'"' -f4)

TEST_LABEL=off
[ -z "$TEST_MODE" ] || TEST_LABEL="ON (rehearsal only: anyone can enroll any address)"

cat <<EOF

== issuer is up ==
public URL : $PUBLIC_URL
DID        : $DID
public key : $X   (Ed25519, base64url "x")
test mode  : $TEST_LABEL

Send the DID and public key to the integrators who should trust you
(OpenLine: docs/RUN_AN_ISSUER.md, "Getting trusted").
EOF
if [ "$MODE" != local ]; then
  echo "HTTPS: the first certificate can take a minute. Check: curl $PUBLIC_URL/health"
fi
