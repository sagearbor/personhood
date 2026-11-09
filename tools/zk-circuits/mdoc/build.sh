#!/usr/bin/env bash
# Build the circuits mobile-id-zk accepts (docs/mobile-id.md), reproducibly.
#
#   tools/zk-circuits/mdoc/build.sh
#
# Pins: Noir 1.0.0-beta.22 (noir_wasm) and Barretenberg 5.0.0 (bb) from
# ../package-lock.json; noir-lang sha256 v0.3.0 and poseidon v0.3.0
# (Apache-2.0). The circuit is personhood's own (src/noir/lib/mdoc,
# Apache-2.0): no zkPassport code, no noir_bigcurve. Outputs:
#   tools/zk-circuits/mdoc/dist/<name>.json.gz, dist/bn254_g1.dat -> host these
#       (MOBILE_ID_ZK_ARTIFACTS_DIR, or a CDN via MOBILE_ID_ZK_ARTIFACTS_URL)
#   src/methods/document-chip/mdoczk/circuits/{circuits.json,vks/*.vk} -> commit
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"
ROOT="$HERE/.."
OUT="$HERE/../../../src/methods/document-chip/mdoczk/circuits"
LIST=$(grep -v '^\s*#' variants.txt | sed '/^\s*$/d')

(cd "$ROOT" && { [ -d node_modules ] || npm ci --no-audit --no-fund; })
# shellcheck disable=SC2086
node gen.mjs $(sed 's#bin/##' <<<"$LIST")
NOIR="$HERE/src/noir"
mkdir -p "$NOIR/archives"
# noir_wasm resolves submodules of sha256/sha256.nr one directory too high
# (nargo does not): fetch the dependencies once, move the file, compile.
rm -rf .work/json
(cd "$ROOT" && node compile.mjs mdoc "$HERE/.work/json" $(head -1 <<<"$LIST") >/dev/null 2>&1) || true
d="$NOIR/libs/noir-lang_sha256@v0.3.0/src"
if [ -f "$d/sha256.nr" ]; then mv "$d/sha256.nr" "$d/sha256/mod.nr"; fi
rm -rf .work/json
# shellcheck disable=SC2086
(cd "$ROOT" && node compile.mjs mdoc "$HERE/.work/json" $LIST)
rm -rf dist
# shellcheck disable=SC2086
(cd "$ROOT" && CIRCUITS_SRC="$HERE" CIRCUITS_LABEL="personhood/tools/zk-circuits/mdoc" node manifest.mjs "$HERE/.work/json" "$HERE/dist" "$OUT" mdoc $LIST)
echo "artifacts in $HERE/dist ($(du -sh dist | cut -f1)); manifest + vks in src/methods/document-chip/mdoczk/circuits/"
