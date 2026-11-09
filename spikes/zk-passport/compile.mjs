// Compile the zkPassport Noir sub-circuits this spike needs, with noir_wasm
// (no nargo binary required). Usage: node compile.mjs <zkpassport-circuits checkout>
import { compile, createFileManager } from "@noir-lang/noir_wasm"
import fs from "fs"
import path from "path"

// One profile per personhood test vector (src/methods/document-chip/icao/testdata).
// The wallet picks the variant from the DSC/SOD algorithms; zkPassport's
// circuit-matcher does that automatically in production.
const PROFILES = {
  // p256/: CSCA+DSC NIST P-256, DSC signed ecdsa-with-SHA256, SOD ecdsa-with-SHA384, LDS SHA-384
  p256: {
    dsc: "bin/sig-check/dsc/tbs_700/ecdsa/nist/p256/sha256",
    id: "bin/sig-check/id-data/tbs_700/ecdsa/nist/p256/sha384",
    integrity: "bin/data-check/integrity/sa_sha384/dg_sha384",
  },
  // rsa-pss/: CSCA RSA-3072 PSS, DSC RSA-2048, SOD RSASSA-PSS/SHA-256 (German style)
  "rsa-pss": {
    dsc: "bin/sig-check/dsc/tbs_700/rsa/pss/3072/sha256",
    id: "bin/sig-check/id-data/tbs_700/rsa/pss/2048/sha256",
    integrity: "bin/data-check/integrity/sa_sha256/dg_sha256",
  },
}
const profile = process.env.PROFILE ?? "p256"
export const CIRCUITS = { ...PROFILES[profile], expiry: "bin/compare/expiry/standard" }

const repo = process.argv[2]
if (!repo) throw new Error("usage: node compile.mjs <zkpassport-circuits checkout>")
const root = path.resolve(repo, "src/noir")
const outDir = `target/${profile}`
fs.mkdirSync(outDir, { recursive: true })
const only = process.argv[3]
for (const [name, rel] of Object.entries(CIRCUITS)) {
  if (only && only !== name) continue
  const t0 = performance.now()
  const fm = createFileManager(root)
  const out = await compile(fm, path.join(root, rel), () => {}, () => {})
  const program = out.program ?? out
  fs.writeFileSync(`${outDir}/${name}.json`, JSON.stringify(program))
  console.log(`${name}: compiled in ${((performance.now() - t0) / 1000).toFixed(1)} s`)
}
