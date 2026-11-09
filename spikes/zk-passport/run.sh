#!/usr/bin/env bash
# Phase-1 zk-passport spike: prove the personhood ICAO test vectors with
# zkPassport's Noir circuits and verify them from Go. See docs/zk-passport.md.
#
#   spikes/zk-passport/run.sh            # both vectors
#   PROFILES=p256 spikes/zk-passport/run.sh
#   HARDWARE_CONCURRENCY=1 ...           # single-threaded proving (phone-like)
#
# Needs node >= 22, git, go. Downloads: npm packages (pinned in package.json,
# about 250 MB) and zkpassport/circuits at a pinned commit.
set -euo pipefail
cd "$(dirname "$0")"

ZKP_COMMIT=11b5e04ce8d1a5d621f8add9abe421b87d3dc97a   # zkpassport/circuits main, 2026-11-03 (v0.21.1)
CIRCUITS=${CIRCUITS_DIR:-target/zkpassport-circuits}

[ -d node_modules ] || npm install --no-audit --no-fund
if [ ! -d "$CIRCUITS/.git" ]; then
  git clone -q https://github.com/zkpassport/circuits "$CIRCUITS"
  git -C "$CIRCUITS" checkout -q "$ZKP_COMMIT"
  # noir_wasm (unlike nargo) keys library sources by dependency alias, so two
  # different crates both aliased "common" collide. Rename one alias; the
  # circuit is unchanged.
  sed -i.bak 's/^common = { path = "..\/common" }/sig_check_common = { path = "..\/common" }/' \
    "$CIRCUITS/src/noir/lib/sig-check/rsa/Nargo.toml"
  sed -i.bak 's/^use common::{/use sig_check_common::{/' "$CIRCUITS/src/noir/lib/sig-check/rsa/src/lib.nr"
fi
NOIR="$CIRCUITS/src/noir"
fix_sha256() {
  # noir_wasm resolves submodules of a file named like its crate
  # (sha256/sha256.nr) one directory too high. Moving the module to mod.nr is
  # the same module to nargo.
  local d="$NOIR/libs/noir-lang_sha256@v0.3.0/src"
  if [ -f "$d/sha256.nr" ]; then mv "$d/sha256.nr" "$d/sha256/mod.nr"; fi
}
prefetch_date() {
  # noir_wasm builds the archive URL from the git URL verbatim, and this one
  # ends in ".git"; fetch the tag archive under the name it looks for.
  local a="$NOIR/archives/madztheo_noir-date.git_archive_v0.5.6.zip"
  mkdir -p "$NOIR/archives"
  [ -f "$a" ] || curl -sfL -o "$a" https://github.com/madztheo/noir-date/archive/refs/tags/v0.5.6.zip
}
prefetch_date

for P in ${PROFILES:-p256 rsa-pss}; do
  echo "== $P"
  # first compile fetches the git deps; fix sha256 and compile again if needed
  PROFILE=$P node compile.mjs "$CIRCUITS" >/dev/null 2>&1 || { fix_sha256; PROFILE=$P node compile.mjs "$CIRCUITS" | grep compiled; }
  PROFILE=$P npx tsx inputs.ts ../../src/methods/document-chip/icao/testdata/$P UTO 2>/dev/null
  PROFILE=$P node prove.mjs 2>/dev/null
done

echo "== Go verifier"
(cd ../../src/methods/document-chip && go test ./zkproof/ -run TestVerify -v 2>&1 | grep -E "verified|PASS|FAIL|ok")
