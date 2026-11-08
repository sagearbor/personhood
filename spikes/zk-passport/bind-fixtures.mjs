// Phase 2: make the Go test fixtures for document-chip-zk with the session
// binding sub-proof (zkPassport's `bind` circuit) in place of `expiry`.
//
//   node bind-fixtures.mjs            (after run.sh has built target/<profile>)
//
// For each test vector it reuses the dsc/id/integrity inputs run.sh built,
// derives the bind inputs from the expiry inputs (same salted values) plus
// the 509-byte bind data for a fixed test challenge and holder DID, proves
// all four sub-proofs with bb 5.0.0, and writes
// src/methods/document-chip/zkproof/testdata/<vector>/{dsc,id,integrity,bind}/{proof,public_inputs,vk}
// and manifest.json. The Go tests recompute the bind data from the same
// challenge and DID (zkproof.BindData), so a mismatch here fails there.
import { Noir } from "@noir-lang/noir_js"
import { execFileSync } from "child_process"
import { createHash } from "crypto"
import fs from "fs"
import os from "os"
import path from "path"

const arch = `${os.arch() === "arm64" ? "arm64" : "amd64"}-${os.platform() === "darwin" ? "macos" : "linux"}`
const BB = process.env.BB ?? path.resolve(`node_modules/@aztec/bb.js/build/${arch}/bb`)
const TARGET = "noir-recursive"
const OUT_ROOT = path.resolve("../../src/methods/document-chip/zkproof/testdata")

// Must match zkproof_test.go.
export const TEST_CHALLENGE = Buffer.alloc(32, 0x5a)
export const TEST_HOLDER_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
// Must match documentchip.ZKScope (Poseidon2 of "personhood:document-chip-zk:v1"); passed in.
const SCOPE = process.env.ZK_SCOPE
if (!SCOPE) throw new Error("set ZK_SCOPE (go test ./zkproof -run TestPrintScope -v prints it)")

function bindData() {
  const d = Buffer.alloc(509)
  TEST_CHALLENGE.copy(d, 0)
  createHash("sha256").update(Buffer.concat([Buffer.from("personhood/zk-bind/v1\0"), Buffer.from(TEST_HOLDER_DID)])).digest().copy(d, 32)
  return [...d]
}

const bind = JSON.parse(fs.readFileSync("target/bind/bind.json", "utf8"))
for (const profile of (process.env.PROFILES ?? "p256 rsa-pss").split(" ")) {
  const dir = `target/${profile}`
  const circuits = {
    dsc: JSON.parse(fs.readFileSync(`${dir}/dsc.json`, "utf8")),
    id: JSON.parse(fs.readFileSync(`${dir}/id.json`, "utf8")),
    integrity: JSON.parse(fs.readFileSync(`${dir}/integrity.json`, "utf8")),
    bind,
  }
  const exp = JSON.parse(fs.readFileSync(`${dir}/expiry.inputs.json`, "utf8"))
  const { min_date, max_date, ...rest } = exp
  const inputs = {
    dsc: JSON.parse(fs.readFileSync(`${dir}/dsc.inputs.json`, "utf8")),
    id: JSON.parse(fs.readFileSync(`${dir}/id.inputs.json`, "utf8")),
    integrity: JSON.parse(fs.readFileSync(`${dir}/integrity.inputs.json`, "utf8")),
    bind: { ...rest, current_date: Math.floor(Date.now() / 1000), service_scope: SCOPE, service_subscope: "0x0", data: bindData() },
  }
  const outDir = path.join(OUT_ROOT, profile)
  fs.rmSync(path.join(outDir, "expiry"), { recursive: true, force: true })
  const manifest = { circuits: {}, registry_root: inputs.dsc.certificate_registry_root, scope: SCOPE, current_date: inputs.bind.current_date }
  for (const stage of ["dsc", "id", "integrity", "bind"]) {
    const c = circuits[stage]
    const name = stage === "bind" ? "bind" : JSON.parse(fs.readFileSync(`${dir}/${stage}.json`, "utf8")).name ?? null
    const { witness } = await new Noir(c).execute(inputs[stage])
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "zkfix-"))
    fs.writeFileSync(`${work}/c.json`, JSON.stringify(c))
    fs.writeFileSync(`${work}/w.gz`, witness)
    execFileSync(BB, ["write_vk", "-t", TARGET, "-b", `${work}/c.json`, "-o", work], { stdio: "ignore" })
    execFileSync(BB, ["prove", "-t", TARGET, "-b", `${work}/c.json`, "-w", `${work}/w.gz`, "-k", `${work}/vk`, "-o", work], { stdio: "ignore" })
    execFileSync(BB, ["verify", "-t", TARGET, "-k", `${work}/vk`, "-p", `${work}/proof`, "-i", `${work}/public_inputs`], { stdio: "ignore" })
    const sd = path.join(outDir, stage)
    fs.mkdirSync(sd, { recursive: true })
    for (const f of ["proof", "public_inputs", "vk"]) fs.copyFileSync(`${work}/${f}`, `${sd}/${f}`)
    fs.rmSync(work, { recursive: true, force: true })
    manifest.circuits[stage] = name
    console.log(`${profile}/${stage}: proved and verified`)
  }
  // circuit names come from the old manifest (compile.mjs does not record them)
  const old = JSON.parse(fs.readFileSync(path.join(outDir, "manifest.json"), "utf8"))
  for (const st of ["dsc", "id", "integrity"]) manifest.circuits[st] = old.circuits[st]
  manifest.circuits.bind = "bind"
  fs.writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify(manifest, null, 1) + "\n")
}
