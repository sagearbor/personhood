// The chain-link fixtures for document-chip-zk (docs/zk-passport.md, "Linking
// an OpenLine chain"): for each test vector, a SECOND bind sub-proof from the
// same integrity commitment as testdata/<vector>/bind, made for an OpenLine
// chain's nullifier scope instead of the issuer's, committing to the same
// bind data (the test challenge and holder DID).
//
//   ZK_LINK_SCOPE=0x... node link-fixtures.mjs     (after run.sh and bind-fixtures.mjs)
//
// It reuses the bind inputs bind-fixtures.mjs derived (the same salted
// values, so comm_in is the integrity proof's comm_out) with service_scope
// replaced and current_date set to the manifest's, proves with bb 5.0.0 and
// writes src/methods/document-chip/zkproof/testdata/<vector>/link/{proof,public_inputs}
// (the verification key is bind's). ZK_LINK_SCOPE is zkproof.ChainScope of
// the test chain id "passport-e2e" (go test ./zkproof -run TestChainScope -v prints it).
import { Noir } from "@noir-lang/noir_js"
import { execFileSync } from "child_process"
import { createHash } from "crypto"
import fs from "fs"
import os from "os"
import path from "path"

const arch = `${os.arch() === "arm64" ? "arm64" : "amd64"}-${os.platform() === "darwin" ? "macos" : "linux"}`
const BB = process.env.BB ?? path.resolve(`node_modules/@aztec/bb.js/build/${arch}/bb`)
const TARGET = "noir-recursive"
const OUT_ROOT = path.resolve(process.env.OUT_ROOT ?? "../../src/methods/document-chip/zkproof/testdata")
const SCOPE = process.env.ZK_LINK_SCOPE
if (!SCOPE) throw new Error("set ZK_LINK_SCOPE")

// Must match zkproof_test.go and bind-fixtures.mjs.
const TEST_CHALLENGE = Buffer.alloc(32, 0x5a)
const TEST_HOLDER_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
function bindData() {
  const d = Buffer.alloc(509)
  TEST_CHALLENGE.copy(d, 0)
  createHash("sha256").update(Buffer.concat([Buffer.from("personhood/zk-bind/v1\0"), Buffer.from(TEST_HOLDER_DID)])).digest().copy(d, 32)
  return [...d]
}

const bind = JSON.parse(fs.readFileSync("target/bind/bind.json", "utf8"))
for (const profile of (process.env.PROFILES ?? "p256 rsa-pss").split(" ")) {
  const outDir = path.join(OUT_ROOT, profile)
  const manifest = JSON.parse(fs.readFileSync(path.join(outDir, "manifest.json"), "utf8"))
  const exp = JSON.parse(fs.readFileSync(`target/${profile}/expiry.inputs.json`, "utf8"))
  const { min_date, max_date, ...rest } = exp
  const inputs = { ...rest, current_date: manifest.current_date, service_scope: SCOPE, service_subscope: "0x0", data: bindData() }
  const { witness } = await new Noir(bind).execute(inputs)
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "zklink-"))
  fs.writeFileSync(`${work}/c.json`, JSON.stringify(bind))
  fs.writeFileSync(`${work}/w.gz`, witness)
  fs.copyFileSync(path.join(outDir, "bind", "vk"), `${work}/vk`)
  execFileSync(BB, ["prove", "-t", TARGET, "-b", `${work}/c.json`, "-w", `${work}/w.gz`, "-k", `${work}/vk`, "-o", work], { stdio: "ignore" })
  execFileSync(BB, ["verify", "-t", TARGET, "-k", `${work}/vk`, "-p", `${work}/proof`, "-i", `${work}/public_inputs`], { stdio: "ignore" })
  const sd = path.join(outDir, "link")
  fs.mkdirSync(sd, { recursive: true })
  for (const f of ["proof", "public_inputs"]) fs.copyFileSync(`${work}/${f}`, `${sd}/${f}`)
  fs.rmSync(work, { recursive: true, force: true })
  manifest.link_scope = SCOPE
  fs.writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify(manifest, null, 1) + "\n")
  console.log(`${profile}/link: proved and verified`)
}
