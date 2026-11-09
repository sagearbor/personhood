#!/usr/bin/env bash
# Phase-1 spike for mobile-id-zk (docs/mobile-id.md): mint specimen mobile
# driving licences with the test issuer (Utopia; no real person, no real
# issuer), prove them with personhood's mdoc circuit, check the circuit's
# soundness, then run the Go verifier tests.
#
#   spikes/mobile-id/run.sh            # needs Go, Node >= 22, network once
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
[ -d node_modules ] || npm install --no-audit --no-fund
"$ROOT/tools/zk-circuits/mdoc/build.sh"
mkdir -p out
gen() { (cd "$ROOT/src/methods/document-chip" && go run ./mdoczk/cmd/mdoc-testvector "$@"); }
gen > out/vector.json
gen > out/vector-reissued.json
gen -doc UT7654321 > out/vector-other.json
gen -handover openid4vp > out/vector-oid4vp.json
gen -extra 40 > out/vector-big.json
J="$ROOT/tools/zk-circuits/mdoc/.work/json"
node prove.mjs out/vector.json "$J/mdoc_p256_msg_2048.json"
THREADS=1 node prove.mjs out/vector.json "$J/mdoc_p256_msg_2048.json"
THREADS=4 node prove.mjs out/vector.json "$J/mdoc_p256_msg_2048.json"
node prove.mjs out/vector-oid4vp.json "$J/mdoc_p256_msg_2048.json"
node prove.mjs out/vector-big.json "$J/mdoc_p256_msg_3072.json"
node circuit-tests.mjs out/vector.json out/vector-reissued.json out/vector-other.json "$J/mdoc_p256_msg_2048.json"
# Regenerate the Go fixtures (session challenge SHA-256("mdoc-test")):
if [ "${UPDATE_FIXTURES:-0}" = 1 ]; then
  T="$ROOT/src/methods/document-chip/mdoczk/testdata"
  FIXTURE="$T/specimen" node prove.mjs out/vector.json "$J/mdoc_p256_msg_2048.json"
  FIXTURE="$T/specimen-oid4vp" node prove.mjs out/vector-oid4vp.json "$J/mdoc_p256_msg_2048.json"
  rm -f "$T"/*/vk
fi
(cd "$ROOT/src/methods/document-chip" && go test ./mdoczk/ -run . && go test . -run MobileID)
