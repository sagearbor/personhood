#!/usr/bin/env bash
# Build the circuit artifacts document-chip-zk accepts, reproducibly.
#
#   tools/zk-circuits/build.sh                     # variants/core.txt
#   VARIANTS=variants/mine.txt tools/zk-circuits/build.sh
#   ZK_INCLUDE_UNLICENSED=1 ...                    # allow ECDSA variants (see README.md)
#
# Pins: zkPassport circuits at ZKP_COMMIT (Apache-2.0), Noir 1.0.0-beta.22
# (noir_wasm) and Barretenberg 5.0.0 (bb from @aztec/bb.js), both from
# package-lock.json. Outputs:
#   tools/zk-circuits/dist/<name>.json.gz, dist/bn254_g1.dat  -> host these (issuer
#       DOCUMENT_CHIP_ZK_ARTIFACTS_DIR, or a CDN via DOCUMENT_CHIP_ZK_ARTIFACTS_URL)
#   src/methods/document-chip/zk/circuits.json, zk/vks/*.vk   -> commit these: the
#       issuer embeds them and accepts only these verification keys
# Run it again after changing the variant list or a pin, and commit the
# zk/ changes in the same PR as the change.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"

ZKP_COMMIT=11b5e04ce8d1a5d621f8add9abe421b87d3dc97a   # zkpassport/circuits main, 2026-11-03 (v0.21.1)
VARIANTS="${VARIANTS:-variants/core.txt}"
WORK="$HERE/.work"
CIRCUITS="$WORK/circuits"
ZKDIR="$HERE/../../src/methods/document-chip/zk"

mapfile_compat() { grep -v '^\s*#' "$1" | sed '/^\s*$/d'; }
LIST=$(mapfile_compat "$VARIANTS")
if [ "${ZK_INCLUDE_UNLICENSED:-0}" != 1 ] && grep -q '/ecdsa/' <<<"$LIST"; then
  echo "The variant list has ECDSA circuits. They depend on noir_bigcurve, which has no" >&2
  echo "license file (README.md). Set ZK_INCLUDE_UNLICENSED=1 to build them anyway." >&2
  exit 1
fi

[ -d node_modules ] || npm ci --no-audit --no-fund
if [ ! -d "$CIRCUITS/.git" ]; then
  mkdir -p "$WORK"
  git clone -q https://github.com/zkpassport/circuits "$CIRCUITS"
fi
git -C "$CIRCUITS" checkout -q "$ZKP_COMMIT"
git -C "$CIRCUITS" checkout -q -- .   # undo earlier workaround edits; reapplied below
NOIR="$CIRCUITS/src/noir"

# noir_wasm workarounds (nargo does not need them; none changes a circuit):
# 1. two different crates are both aliased "common": rename one alias.
sed -i.bak 's/^common = { path = "..\/common" }/sig_check_common = { path = "..\/common" }/' "$NOIR/lib/sig-check/rsa/Nargo.toml"
sed -i.bak 's/^use common::{/use sig_check_common::{/' "$NOIR/lib/sig-check/rsa/src/lib.nr"
# 2. noir_wasm cannot fetch a git dependency whose URL ends in ".git" (noir-date).
mkdir -p "$NOIR/archives"
A="$NOIR/archives/madztheo_noir-date.git_archive_v0.5.6.zip"
[ -f "$A" ] || curl -sfL -o "$A" https://github.com/madztheo/noir-date/archive/refs/tags/v0.5.6.zip
# 3. noir_wasm resolves submodules of sha256/sha256.nr one directory too high.
fix_sha256() {
  local d="$NOIR/libs/noir-lang_sha256@v0.3.0/src"
  if [ -f "$d/sha256.nr" ]; then mv "$d/sha256.nr" "$d/sha256/mod.nr"; fi
}

# shellcheck disable=SC2086
node compile.mjs "$CIRCUITS" "$WORK/json" $(head -1 <<<"$LIST") >/dev/null 2>&1 || true   # fetches git deps
fix_sha256
# shellcheck disable=SC2086
node compile.mjs "$CIRCUITS" "$WORK/json" $LIST

rm -rf dist
# shellcheck disable=SC2086
CIRCUITS_SRC="$CIRCUITS" node manifest.mjs "$WORK/json" dist "$ZKDIR" "$ZKP_COMMIT" $LIST
echo "artifacts in $HERE/dist ($(du -sh dist | cut -f1)); manifest + vks in src/methods/document-chip/zk/"
