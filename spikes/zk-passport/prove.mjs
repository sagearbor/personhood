// Solve each sub-circuit's witness with noir_js, then prove and verify it with
// the native bb CLI (shipped inside @aztec/bb.js). Prints prove time, peak
// memory, proof size and verify time per sub-proof.
// Usage: node prove.mjs   (after compile.mjs and inputs.ts)
import { Noir } from "@noir-lang/noir_js"
import { execFileSync } from "child_process"
import fs from "fs"
import os from "os"
import path from "path"

const arch = `${os.arch() === "arm64" ? "arm64" : "amd64"}-${os.platform() === "darwin" ? "macos" : "linux"}`
const BB = path.resolve(`node_modules/@aztec/bb.js/build/${arch}/bb`)
const TARGET = "noir-recursive"
const OUT = `target/${process.env.PROFILE ?? "p256"}`

function peakMB(stderr) {
  const m = stderr.match(/(\d+)\s+maximum resident set size/) // macOS: bytes
  if (m) return (Number(m[1]) / 1048576).toFixed(0)
  const l = stderr.match(/Maximum resident set size \(kbytes\): (\d+)/) // GNU time: kB
  return l ? (Number(l[1]) / 1024).toFixed(0) : "?"
}

const rows = []
for (const name of ["dsc", "id", "integrity", "expiry"]) {
  const circuit = JSON.parse(fs.readFileSync(`${OUT}/${name}.json`, "utf8"))
  const inputs = JSON.parse(fs.readFileSync(`${OUT}/${name}.inputs.json`, "utf8"))
  const dir = `${OUT}/${name}`
  fs.mkdirSync(dir, { recursive: true })

  let t0 = performance.now()
  const { witness, returnValue } = await new Noir(circuit).execute(inputs)
  const witnessMs = performance.now() - t0
  fs.writeFileSync(`${dir}/witness.gz`, witness)

  // vk is per circuit, generated once (it ships with the issuer)
  execFileSync(BB, ["write_vk", "-t", TARGET, "-b", `${OUT}/${name}.json`, "-o", dir], { stdio: "ignore" })

  // prove (with peak memory)
  t0 = performance.now()
  const r = require_spawn(["prove", "-t", TARGET, "-b", `${OUT}/${name}.json`, "-w", `${dir}/witness.gz`, "-k", `${dir}/vk`, "-o", dir])
  const proveMs = performance.now() - t0

  t0 = performance.now()
  execFileSync(BB, ["verify", "-t", TARGET, "-k", `${dir}/vk`, "-p", `${dir}/proof`, "-i", `${dir}/public_inputs`], { stdio: "ignore" })
  const verifyMs = performance.now() - t0

  rows.push({
    circuit: name,
    witness_s: (witnessMs / 1000).toFixed(2),
    prove_s: (proveMs / 1000).toFixed(2),
    prove_peak_MB: r.peak,
    proof_bytes: fs.statSync(`${dir}/proof`).size,
    public_inputs: fs.statSync(`${dir}/public_inputs`).size / 32,
    verify_ms: verifyMs.toFixed(0),
    return: Array.isArray(returnValue) ? returnValue : [returnValue],
  })
}

function require_spawn(args) {
  const mac = os.platform() === "darwin"
  const res = execFileSync("/bin/sh", ["-c", `/usr/bin/time ${mac ? "-l" : "-v"} "${BB}" ${args.map((a) => `'${a}'`).join(" ")} 2>&1 1>/dev/null`], { encoding: "utf8" })
  return { peak: peakMB(res) }
}

console.table(rows.map(({ return: _r, ...x }) => x))
fs.writeFileSync(`${OUT}/results.json`, JSON.stringify(rows, null, 2))
