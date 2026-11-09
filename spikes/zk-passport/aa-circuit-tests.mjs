// Circuit tests for the Active Authentication variants that have no test
// passport: a synthetic passport (the rsa-pss vector's DG1 and salts, a
// fresh eContent listing a fresh DG15) for each AA algorithm, so every
// variant family runs with a real chip-style signature, and the wrong ones
// are refused. Only the aa sub-proof is exercised: its comm_in is computed
// here exactly as the id circuit computes it.
//
//   node aa-circuit-tests.mjs [--prove]      (circuits from tools/zk-circuits/.work/json)
//
// --prove also proves (bb, all cores) one circuit per family and prints
// prove time and peak memory.
import { Noir } from "@noir-lang/noir_js"
import { poseidon2Hash } from "@zkpassport/poseidon2"
import { execFileSync, spawnSync } from "child_process"
import { createHash, createSign, generateKeyPairSync } from "crypto"
import fs from "fs"
import os from "os"
import path from "path"

const arch = `${os.arch() === "arm64" ? "arm64" : "amd64"}-${os.platform() === "darwin" ? "macos" : "linux"}`
const BB = process.env.BB ?? path.resolve(`node_modules/@aztec/bb.js/build/${arch}/bb`)
const COMPILED = path.resolve(process.env.AA_JSON ?? "../../tools/zk-circuits/.work/json")
const PROVE = process.argv.includes("--prove")

const HASH = { sha1: [20, 0x33], sha224: [28, 0x38], sha256: [32, 0x34], sha384: [48, 0x36], sha512: [64, 0x35] }
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
const pad = (b, n) => {
  const o = Buffer.alloc(n)
  Buffer.from(b).copy(o)
  return o
}
function packBE(b) {
  const out = []
  for (let end = b.length; end > 0; end -= 31) out.push(big(b.subarray(Math.max(0, end - 31), end)))
  return out
}
function der(tag, content) {
  const l = content.length
  const len = l < 0x80 ? [l] : l < 0x100 ? [0x81, l] : [0x82, l >> 8, l & 0xff]
  return Buffer.concat([Buffer.from([tag, ...len]), content])
}

const base = JSON.parse(fs.readFileSync("target/rsa-pss/integrity.inputs.json", "utf8"))
const dg1 = Buffer.from(base.salted_dg1.value)
const sa = Buffer.from(base.signed_attributes)

/** aa inputs for a passport whose eContent lists `dg15` (or not, when null). */
function passport(dg15, dgHash) {
  const entries = [1, 2, ...(dg15 ? [15] : [])].map((dg) => {
    const data = dg === 15 ? dg15 : Buffer.from(`DG${dg}`)
    const h = createHash(dgHash).update(data).digest()
    return der(0x30, Buffer.concat([der(0x02, Buffer.from([dg])), der(0x04, h)]))
  })
  const eContent = der(0x30, Buffer.concat([der(0x02, Buffer.from([0])), der(0x30, Buffer.from("06", "hex")), der(0x30, Buffer.concat(entries))]))
  const ec = pad(eContent, 700)
  const salt = 7n
  const pn = 12345n
  const country = big(dg1.subarray(7, 10))
  const saLen = sa[1] < 0x80 ? 2 + sa[1] : sa[1] === 0x81 ? 3 + sa[2] : 4 + sa[2] * 256 + sa[3]
  const comm = poseidon2Hash([salt, country, ...packBE(sa), BigInt(saLen), ...packBE(dg1), ...packBE(ec), pn])
  return {
    comm_in: "0x" + comm.toString(16),
    salt_in: "0x" + salt.toString(16),
    dg1: [...dg1],
    signed_attributes: [...sa],
    signed_attributes_size: saLen,
    e_content: [...ec],
    private_nullifier: "0x" + pn.toString(16),
  }
}

function rsaKey(bits, e = 65537) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: bits, publicExponent: e })
  const jwk = privateKey.export({ format: "jwk" })
  const dg15 = der(0x6f, publicKey.export({ type: "spki", format: "der" }))
  return { n: big(Buffer.from(jwk.n, "base64url")), d: big(Buffer.from(jwk.d, "base64url")), k: bits / 8, dg15 }
}

/** ISO/IEC 9796-2 scheme 1 signature; explicit trailer (hash id, 0xCC) unless implicit SHA-1 (0xBC). */
function sign9796(key, aaHash, challenge, { implicit = aaHash === "sha1", negate = false } = {}) {
  const [hl, id] = HASH[aaHash]
  const t = implicit ? 1 : 2
  const m1 = Buffer.alloc(key.k - 1 - hl - t, 0x5c)
  const h = createHash(aaHash).update(Buffer.concat([m1, challenge])).digest()
  const j = Buffer.concat([Buffer.from([0x6a]), m1, h, Buffer.from(implicit ? [0xbc] : [id, 0xcc])])
  let s = modpow(big(j), key.d, key.n)
  // A chip may return the signature of n - J (some do, for even-exponent
  // compatibility); the circuit accepts J or n - J.
  if (negate) s = modpow(key.n - big(j), key.d, key.n)
  return bytes(s, key.k)
}

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
function ecKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
  return { privateKey, dg15: der(0x6f, publicKey.export({ type: "spki", format: "der" })) }
}
function signEcdsa(key, aaHash, challenge) {
  const sig = createSign(aaHash).update(challenge).sign({ key: key.privateKey, dsaEncoding: "ieee-p1363" })
  let s = big(sig.subarray(32))
  if (s > P256_N / 2n) s = P256_N - s // low-s (BSI plain format allows either)
  return Buffer.concat([sig.subarray(0, 32), bytes(s, 32)])
}

const circuits = {}
const circuit = (name) => (circuits[name] ??= JSON.parse(fs.readFileSync(path.join(COMPILED, `${name}.json`), "utf8")))
let failures = 0
async function expect(ok, what, name, inputs) {
  let err = null
  try {
    await new Noir(circuit(name)).execute(inputs)
  } catch (e) {
    err = e
  }
  const pass = ok ? !err : !!err
  if (!pass) failures++
  const why = err ? ` (${String(err.message).split("\n")[0].slice(0, 90)})` : ""
  console.log(`${pass ? "ok  " : "FAIL"} ${name}: ${what}${ok ? "" : why}`)
}

async function proveOnce(name, inputs) {
  const { witness } = await new Noir(circuit(name)).execute(inputs)
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "aaprove-"))
  fs.writeFileSync(`${work}/c.json`, JSON.stringify(circuit(name)))
  fs.writeFileSync(`${work}/w.gz`, witness)
  execFileSync(BB, ["write_vk", "-t", "noir-recursive", "-b", `${work}/c.json`, "-o", work], { stdio: "ignore" })
  const timeFlag = os.platform() === "darwin" ? "-l" : "-v"
  const r = spawnSync("/usr/bin/time", [timeFlag, BB, "prove", "-t", "noir-recursive", "-b", `${work}/c.json`, "-w", `${work}/w.gz`, "-k", `${work}/vk`, "-o", work], { encoding: "utf8" })
  const t1 = /([\d.]+) real/.exec(r.stderr)?.[1] ?? /Elapsed.*?([\d:.]+)$/m.exec(r.stderr)?.[1]
  const rss = /(\d+)\s+maximum resident set size/.exec(r.stderr)?.[1]
  execFileSync(BB, ["verify", "-t", "noir-recursive", "-k", `${work}/vk`, "-p", `${work}/proof`, "-i", `${work}/public_inputs`], { stdio: "ignore" })
  fs.rmSync(work, { recursive: true, force: true })
  console.log(`     proved ${name}: ${t1} s, peak ${rss ? Math.round(rss / 1048576) : "?"} MB`)
}

const ch = Buffer.from("a1b2c3d4e5f60718", "hex")
const other = Buffer.from("0000000000000001", "hex")
const field = (b) => hex(b)

const names = fs.readdirSync(COMPILED).filter((f) => f.startsWith("aa_dg_")).map((f) => f.slice(0, -5))
const proved = new Set()
for (const name of names.sort()) {
  const m = name.match(/^aa_dg_(sha\d+)_(rsa_(\d+)|ecdsa_p256)_(sha\d+)$/)
  const [, dgHash, , bits, aaHash] = m
  if (bits) {
    const key = rsaKey(Number(bits))
    const p = passport(key.dg15, dgHash)
    const inp = (sig, c = ch, dg15 = key.dg15) => ({
      ...p,
      aa_challenge: field(c),
      dg15: [...pad(dg15, 512)],
      aa_signature: [...sig],
      aa_redc_param: [...bytes((1n << BigInt(2 * key.k * 8 + 6)) / key.n, key.k + 1)],
    })
    await expect(true, "chip signature over the challenge", name, inp(sign9796(key, aaHash, ch)))
    await expect(true, "signature of n - J", name, inp(sign9796(key, aaHash, ch, { negate: true })))
    if (aaHash === "sha1") await expect(true, "explicit SHA-1 trailer 0x33CC", name, inp(sign9796(key, aaHash, ch, { implicit: false })))
    await expect(false, "signature over another challenge (replayed)", name, inp(sign9796(key, aaHash, other)))
    const other15 = rsaKey(Number(bits))
    await expect(false, "another chip's key and signature (DG15 not in this EF.SOD)", name, inp(sign9796(other15, aaHash, ch), ch, other15.dg15))
    await expect(false, "another key's signature under this DG15", name, inp(sign9796(other15, aaHash, ch)))
    await expect(false, "wrong comm_in (another passport)", name, { ...inp(sign9796(key, aaHash, ch)), comm_in: "0x1" })
    const wrongHash = aaHash === "sha256" ? "sha1" : "sha256"
    await expect(false, `signature with ${wrongHash} instead of ${aaHash}`, name, inp(sign9796(key, wrongHash, ch, { implicit: false })))
    if (PROVE && !proved.has(`rsa${bits}`)) {
      proved.add(`rsa${bits}`)
      await proveOnce(name, inp(sign9796(key, aaHash, ch)))
    }
  } else {
    const key = ecKey()
    const p = passport(key.dg15, dgHash)
    const inp = (sig, c = ch, dg15 = key.dg15) => ({ ...p, aa_challenge: field(c), dg15: [...pad(dg15, 512)], aa_signature: [...sig] })
    await expect(true, "chip signature over the challenge", name, inp(signEcdsa(key, aaHash, ch)))
    await expect(false, "signature over another challenge (replayed)", name, inp(signEcdsa(key, aaHash, other)))
    const k2 = ecKey()
    await expect(false, "another chip's key and signature (DG15 not in this EF.SOD)", name, inp(signEcdsa(k2, aaHash, ch), ch, k2.dg15))
    await expect(false, "another key's signature under this DG15", name, inp(signEcdsa(k2, aaHash, ch)))
    if (PROVE && !proved.has("p256")) {
      proved.add("p256")
      await proveOnce(name, inp(signEcdsa(key, aaHash, ch)))
    }
  }
}
// aa_absent
if (fs.existsSync(path.join(COMPILED, "aa_absent.json"))) {
  const key = rsaKey(1024)
  await expect(true, "passport without DG15", "aa_absent", { ...passport(null, "sha256"), aa_challenge: field(ch) })
  await expect(false, "passport with DG15", "aa_absent", { ...passport(key.dg15, "sha256"), aa_challenge: field(ch) })
  const p = passport(null, "sha256")
  await expect(false, "challenge wider than 8 bytes", "aa_absent", { ...p, aa_challenge: "0x10000000000000000" })
  if (PROVE) await proveOnce("aa_absent", { ...p, aa_challenge: field(ch) })
}
console.log(failures ? `${failures} FAILED` : "all AA circuit checks passed")
process.exit(failures ? 1 : 0)
