// Phase 3: Go test fixtures for the Active Authentication sub-proof ("aa").
//
//   node aa-fixtures.mjs     (after run.sh and bind-fixtures.mjs; needs the
//                             aa circuits compiled by tools/zk-circuits/build.sh)
//
// For each test vector it reuses the integrity inputs run.sh built (the aa
// circuit opens the same commitment the integrity circuit opens), and proves:
//   rsa-pss  (EF.SOD lists DG15, RSA-1024 AA key in icao/testdata/rsa-pss/aa.key):
//            aa_dg_sha256_rsa_1024_sha1 with the "chip" (aa.key) signing the
//            AA challenge derived from the fixed test session challenge;
//            plus aa-wrong-challenge/: the same chip answering another challenge
//   p256     (no DG15): aa_absent
// and writes src/methods/document-chip/zkproof/testdata/<vector>/aa*/{proof,public_inputs,vk}
// and the circuit name into manifest.json.
import { Noir } from "@noir-lang/noir_js"
import { execFileSync } from "child_process"
import { createHash, createPrivateKey } from "crypto"
import fs from "fs"
import os from "os"
import path from "path"
// Must match zkproof_test.go (and bind-fixtures.mjs).
const TEST_CHALLENGE = Buffer.alloc(32, 0x5a)

const arch = `${os.arch() === "arm64" ? "arm64" : "amd64"}-${os.platform() === "darwin" ? "macos" : "linux"}`
const BB = process.env.BB ?? path.resolve(`node_modules/@aztec/bb.js/build/${arch}/bb`)
const TARGET = "noir-recursive"
const OUT_ROOT = path.resolve("../../src/methods/document-chip/zkproof/testdata")
const VECTORS = path.resolve("../../src/methods/document-chip/icao/testdata")
const COMPILED = path.resolve(process.env.AA_JSON ?? "../../tools/zk-circuits/.work/json")

// Must match zkproof.AAChallenge.
export function aaChallenge(sessionChallenge) {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from("personhood/zk-aa/v1\0"), sessionChallenge]))
    .digest()
    .subarray(0, 8)
}

const hex = (b) => "0x" + Buffer.from(b).toString("hex")
const big = (b) => BigInt("0x" + (Buffer.from(b).toString("hex") || "0"))
function bytes(v, len) {
  const out = Buffer.alloc(len)
  let x = v
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  if (x !== 0n) throw new Error("value too long")
  return out
}
function modpow(b, e, m) {
  let r = 1n
  b %= m
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m
    b = (b * b) % m
    e >>= 1n
  }
  return r
}
const b64u = (s) => Buffer.from(s, "base64url")

/** ISO/IEC 9796-2 scheme 1 (SHA-1, trailer 0xBC) signature, as an AA chip makes it. */
export function sign9796(keyPem, challenge) {
  const jwk = createPrivateKey(keyPem).export({ format: "jwk" })
  const n = big(b64u(jwk.n))
  const d = big(b64u(jwk.d))
  const k = b64u(jwk.n).length
  const m1 = Buffer.alloc(k - 22)
  for (let i = 0; i < m1.length; i++) m1[i] = (i * 37 + 11) & 0xff // the chip's own nonce
  const h = createHash("sha1").update(Buffer.concat([m1, challenge])).digest()
  const j = Buffer.concat([Buffer.from([0x6a]), m1, h, Buffer.from([0xbc])])
  return { sig: bytes(modpow(big(j), d, n), k), n, k }
}

function derLength(b) {
  if (b[1] < 0x80) return 2 + b[1]
  if (b[1] === 0x81) return 3 + b[2]
  return 4 + b[2] * 256 + b[3]
}

function aaInputs(profile, extra) {
  const integ = JSON.parse(fs.readFileSync(`target/${profile}/integrity.inputs.json`, "utf8"))
  return {
    comm_in: integ.comm_in,
    salt_in: integ.salt_in,
    dg1: integ.salted_dg1.value,
    signed_attributes: integ.signed_attributes,
    signed_attributes_size: derLength(integ.signed_attributes),
    e_content: integ.e_content,
    private_nullifier: integ.salted_private_nullifier.value,
    ...extra,
  }
}

async function prove(circuitName, inputs, outDir) {
  const c = JSON.parse(fs.readFileSync(path.join(COMPILED, `${circuitName}.json`), "utf8"))
  const { witness } = await new Noir(c).execute(inputs)
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "zkfix-"))
  fs.writeFileSync(`${work}/c.json`, JSON.stringify(c))
  fs.writeFileSync(`${work}/w.gz`, witness)
  execFileSync(BB, ["write_vk", "-t", TARGET, "-b", `${work}/c.json`, "-o", work], { stdio: "ignore" })
  const t0 = Date.now()
  execFileSync(BB, ["prove", "-t", TARGET, "-b", `${work}/c.json`, "-w", `${work}/w.gz`, "-k", `${work}/vk`, "-o", work], { stdio: "ignore" })
  const ms = Date.now() - t0
  execFileSync(BB, ["verify", "-t", TARGET, "-k", `${work}/vk`, "-p", `${work}/proof`, "-i", `${work}/public_inputs`], { stdio: "ignore" })
  fs.mkdirSync(outDir, { recursive: true })
  for (const f of ["proof", "public_inputs", "vk"]) fs.copyFileSync(`${work}/${f}`, `${outDir}/${f}`)
  fs.rmSync(work, { recursive: true, force: true })
  console.log(`${path.relative(OUT_ROOT, outDir)}: ${circuitName} proved (${ms} ms) and verified`)
}

function setManifest(profile, name) {
  const f = path.join(OUT_ROOT, profile, "manifest.json")
  const m = JSON.parse(fs.readFileSync(f, "utf8"))
  m.circuits.aa = name
  m.aa_challenge = hex(aaChallenge(TEST_CHALLENGE))
  fs.writeFileSync(f, JSON.stringify(m, null, 1) + "\n")
}

const challenge = aaChallenge(TEST_CHALLENGE)

{
  const profile = "rsa-pss"
  const name = "aa_dg_sha256_rsa_1024_sha1"
  const dg15 = fs.readFileSync(`${VECTORS}/${profile}/EF.DG15`)
  const key = fs.readFileSync(`${VECTORS}/${profile}/aa.key`)
  const dg15Padded = Buffer.alloc(512)
  dg15.copy(dg15Padded)
  const rsa = (ch) => {
    const { sig, n, k } = sign9796(key, ch)
    return {
      dg15: [...dg15Padded],
      aa_signature: [...sig],
      aa_redc_param: [...bytes((1n << BigInt(2 * k * 8 + 6)) / n, k + 1)],
    }
  }
  await prove(name, aaInputs(profile, { aa_challenge: hex(challenge), ...rsa(challenge) }), path.join(OUT_ROOT, profile, "aa"))
  // The chip answered a different challenge (an older session's): a valid
  // proof, but for that challenge, so the issuer must refuse it.
  const other = Buffer.from("0102030405060708", "hex")
  await prove(name, aaInputs(profile, { aa_challenge: hex(other), ...rsa(other) }), path.join(OUT_ROOT, profile, "aa-wrong-challenge"))
  setManifest(profile, name)

  // Negative witnesses: these must not produce a proof at all.
  const mustFail = async (what, inputs, circuit = name) => {
    const c = JSON.parse(fs.readFileSync(path.join(COMPILED, `${circuit}.json`), "utf8"))
    try {
      await new Noir(c).execute(inputs)
    } catch {
      console.log(`${profile}: ${what}: refused by the circuit (good)`)
      return
    }
    throw new Error(`${profile}: ${what}: the circuit accepted it`)
  }
  // a signature over another challenge, presented for this one (replayed AA signature)
  await mustFail("replayed AA signature", aaInputs(profile, { aa_challenge: hex(challenge), ...rsa(other) }))
  // DG15 of another passport (bp256's key would not even parse as RSA; make a fresh RSA-1024 DG15)
  const foreign = fs.readFileSync(`${VECTORS}/${profile}/EF.DG15`)
  const flipped = Buffer.from(foreign)
  flipped[flipped.length - 10] ^= 1 // another modulus: its hash is not in this EF.SOD
  const fp = Buffer.alloc(512)
  flipped.copy(fp)
  await mustFail("DG15 not in EF.SOD", aaInputs(profile, { aa_challenge: hex(challenge), ...rsa(challenge), dg15: [...fp] }))
  // a passport with DG15 trying to claim it has none
  await mustFail("aa_absent for a passport with DG15", aaInputs(profile, { aa_challenge: hex(challenge) }), "aa_absent")
}

{
  const profile = "p256"
  await prove("aa_absent", aaInputs(profile, { aa_challenge: hex(challenge) }), path.join(OUT_ROOT, profile, "aa"))
  setManifest(profile, "aa_absent")
}
