// Prove a specimen mobile driving licence (out/vector.json from
// mdoc-testvector) with the mdoc circuit: build the inputs with the wallet's
// input builder (mdocInputs.ts), solve the witness with noir_js, prove and
// verify with the native bb CLI. Prints timings, peak memory and sizes, and
// writes the proof as a Go fixture when FIXTURE=<dir> is set.
//
//   node prove.mjs [vector.json] [circuit.json]
import { Noir } from "@noir-lang/noir_js"
import { execFileSync } from "child_process"
import fs from "fs"
import os from "os"
import path from "path"
import { buildInputs, parseDeviceResponse } from "./mdocInputs.ts"

const arch = `${os.arch() === "arm64" ? "arm64" : "amd64"}-${os.platform() === "darwin" ? "macos" : "linux"}`
const BB = process.env.BB ?? path.resolve(`node_modules/@aztec/bb.js/build/${arch}/bb`)
const TARGET = "noir-recursive"
const vecPath = process.argv[2] ?? "out/vector.json"
const circPath = process.argv[3] ?? "../../tools/zk-circuits/mdoc/.work/json/mdoc_p256_msg_3072.json"
const name = path.basename(circPath, ".json")
const msgSize = Number(name.match(/_(\d+)$/)[1])
const vec = JSON.parse(fs.readFileSync(vecPath, "utf8"))
const hexb = (h) => Uint8Array.from(Buffer.from(h, "hex"))

const t0 = performance.now()
const parsed = parseDeviceResponse(Uint8Array.from(Buffer.from(vec.device_response_b64, "base64")))
const e = vec.registry.entries[vec.iaca_index]
const inputs = buildInputs(
  parsed,
  { jurisdiction: e.jurisdiction, x: hexb(e.x), y: hexb(e.y), index: vec.iaca_index, path: vec.iaca_path },
  { registryRoot: vec.registry.root, scope: vec.scope, now: vec.now, sessionTranscript: hexb(vec.session_transcript), transcriptHash: hexb(vec.transcript_hash) },
  msgSize,
)
const inputsMs = performance.now() - t0

const circuit = JSON.parse(fs.readFileSync(circPath, "utf8"))
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mdoc-prove-"))
let t = performance.now()
const { witness, returnValue } = await new Noir(circuit).execute(inputs)
const witnessMs = performance.now() - t
fs.writeFileSync(`${dir}/witness.gz`, witness)
execFileSync(BB, ["write_vk", "-t", TARGET, "-b", circPath, "-o", dir], { stdio: "ignore" })
const threads = process.env.THREADS
t = performance.now()
const mac = os.platform() === "darwin"
const timeOut = execFileSync("/bin/sh", ["-c", `${threads ? `HARDWARE_CONCURRENCY=${threads} ` : ""}/usr/bin/time ${mac ? "-l" : "-v"} '${BB}' prove -t ${TARGET} -b '${circPath}' -w '${dir}/witness.gz' -k '${dir}/vk' -o '${dir}' 2>&1 1>/dev/null`], { encoding: "utf8" })
const proveMs = performance.now() - t
const peak = mac ? Number(timeOut.match(/(\d+)\s+maximum resident set size/)[1]) / 1048576 : Number(timeOut.match(/Maximum resident set size \(kbytes\): (\d+)/)[1]) / 1024
t = performance.now()
execFileSync(BB, ["verify", "-t", TARGET, "-k", `${dir}/vk`, "-p", `${dir}/proof`, "-i", `${dir}/public_inputs`], { stdio: "ignore" })
const verifyMs = performance.now() - t
const row = {
  circuit: name,
  mso_bytes: vec.mso_bytes,
  inputs_ms: inputsMs.toFixed(0),
  witness_s: (witnessMs / 1000).toFixed(2),
  prove_s: (proveMs / 1000).toFixed(2),
  threads: threads ?? "all",
  prove_peak_MB: peak.toFixed(0),
  proof_bytes: fs.statSync(`${dir}/proof`).size,
  public_inputs: fs.statSync(`${dir}/public_inputs`).size / 32,
  verify_ms: verifyMs.toFixed(0),
  nullifier: returnValue,
  expected: vec.expected_nullifier,
}
console.log(JSON.stringify(row, null, 1))
if (BigInt(returnValue) !== BigInt(vec.expected_nullifier)) throw new Error("nullifier differs from the expected value")
if (process.env.FIXTURE) {
  fs.mkdirSync(process.env.FIXTURE, { recursive: true })
  for (const f of ["proof", "public_inputs", "vk"]) fs.copyFileSync(`${dir}/${f}`, path.join(process.env.FIXTURE, f))
  if (process.env.INPUTS) fs.writeFileSync(path.join(process.env.FIXTURE, "inputs.json"), JSON.stringify(inputs))
  fs.writeFileSync(path.join(process.env.FIXTURE, "vector.json"), JSON.stringify({ ...vec, circuit: name, measured: row }, null, 1))
}
