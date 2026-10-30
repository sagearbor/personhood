#!/usr/bin/env bash
# scripts/issuer-kit/backup.sh — one file holding everything needed to rebuild
# this issuer: issuer.env (signing key, one-inbox-one-voter key, admin token,
# settings) and a snapshot of the Redis data (revocations, status-list slots,
# one-inbox-one-voter seeds, open sessions).
#
#   ./backup.sh [output-dir]    default: ./backups
#
# The output is a mode-0600 .tar.gz. It contains the signing key: keep it
# off this machine, somewhere only you can read (an encrypted USB stick, a
# password manager's file attachment). Restore: docs/RUN_AN_ISSUER.md.
set -euo pipefail
cd "$(dirname "$0")"
[ -f issuer.env ] || { echo "backup.sh: no issuer.env here; nothing to back up" >&2; exit 1; }
OUT_DIR="${1:-backups}"
umask 077
mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cp issuer.env "$WORK/issuer.env"
docker compose exec -T redis redis-cli SAVE >/dev/null
docker compose exec -T redis sh -c 'tar -C /data -cf - .' >"$WORK/redis-data.tar"
tar -C "$WORK" -czf "$OUT_DIR/personhood-issuer-$STAMP.tar.gz" issuer.env redis-data.tar
chmod 600 "$OUT_DIR/personhood-issuer-$STAMP.tar.gz"
echo "wrote $OUT_DIR/personhood-issuer-$STAMP.tar.gz (contains the signing key: move it off this machine)"
