#!/usr/bin/env bash
# scripts/test-all.sh — run `go test -race` in every module listed in go.work.
#
# The module list is derived from go.work so a newly added module is covered
# automatically (CI and the RUNBOOK both call this). Extra arguments are passed
# through to `go test`, e.g.:
#
#   bash scripts/test-all.sh                 # default build
#   bash scripts/test-all.sh -tags sendgrid  # with a build tag
#
# Exits non-zero on the first failing module.
set -euo pipefail

cd "$(dirname "$0")/.."

mods=$(awk '/^use \(/{inuse=1; next} /^\)/{inuse=0} inuse && NF {print $1}' go.work)
if [ -z "$mods" ]; then
  echo "test-all: no modules found in go.work" >&2
  exit 1
fi

for m in $mods; do
  echo "=== $m ==="
  # Stub modules (e.g. src/methods/phone-liveness) have a go.mod but no
  # packages yet; `go test` would exit non-zero on them, so skip those.
  if ! (cd "$m" && go list ./... 2>/dev/null | grep -q .); then
    echo "(no packages — skipped)"
    continue
  fi
  (cd "$m" && go test -race -count=1 "$@" ./...)
done
echo "test-all: all modules green"
