// Soundness checks for the mdoc circuit: every tampered input must make
// witness generation fail; a re-issued licence (new MSO, device key, salts,
// IACA key of the same jurisdiction) must give the same nullifier, another
// document number another one.
//
//   node circuit-tests.mjs <vector.json> <vector-reissued.json> <vector-other.json> [circuit.json]
import { Noir } from "@noir-lang/noir_js"
import fs from "fs"
import { buildInputs, parseDeviceResponse } from "./mdocInputs.ts"

const [v1, v2, v3, circ = "../../tools/zk-circuits/mdoc/.work/json/mdoc_p256_msg_2048.json"] = process.argv.slice(2)
const msgSize = Number(circ.match(/_(\d+)\.json$/)[1])
const noir = new Noir(JSON.parse(fs.readFileSync(circ, "utf8")))
const hexb = (h) => Uint8Array.from(Buffer.from(h, "hex"))
function inputsOf(path, over = {}) {
  const vec = JSON.parse(fs.readFileSync(path, "utf8"))
  const p = parseDeviceResponse(Uint8Array.from(Buffer.from(vec.device_response_b64, "base64")))
  const e = vec.registry.entries[0]
  return {
    vec,
    inputs: buildInputs(
      p,
      { jurisdiction: e.jurisdiction, x: hexb(e.x), y: hexb(e.y), index: 0, path: vec.iaca_path },
      { registryRoot: vec.registry.root, scope: vec.scope, now: over.now ?? vec.now, sessionTranscript: hexb(vec.session_transcript), transcriptHash: hexb(vec.transcript_hash) },
      msgSize,
    ),
  }
}
let pass = 0, failures = 0
async function expectFail(label, mutate) {
  const { inputs } = inputsOf(v1)
  mutate(inputs)
  try {
    await noir.execute(inputs)
    console.log(`FAIL (accepted): ${label}`)
    failures++
  } catch {
    pass++
    console.log(`ok   refused: ${label}`)
  }
}
const flip = (a, i) => (a[i] ^= 1)
const base = inputsOf(v1)
const n1 = (await noir.execute(base.inputs)).returnValue
console.log(`ok   accepted: the specimen licence, nullifier ${n1}`)
await expectFail("another session's transcript hash", (x) => (x.transcript_hash_lo = "0x" + "11".repeat(16)))
await expectFail("now after validUntil", (x) => (x.now = "0x" + Buffer.from("2099-01-01T00:00:00Z").toString("hex")))
await expectFail("now before validFrom", (x) => (x.now = "0x" + Buffer.from("2001-01-01T00:00:00Z").toString("hex")))
await expectFail("registry root not ours", (x) => (x.registry_root = "0x01"))
await expectFail("another jurisdiction for the IACA", (x) => (x.jurisdiction = "0x" + Buffer.from("US-CA").toString("hex")))
await expectFail("document number changed in the item", (x) => flip(x.item, x.item_len - 1))
await expectFail("document number item's salt changed", (x) => flip(x.item, 40))
await expectFail("issuer signature flipped", (x) => flip(x.issuer_sig, 5))
await expectFail("MSO byte changed", (x) => flip(x.issuer_msg, x.issuer_msg_len - 30))
await expectFail("document signer certificate changed", (x) => flip(x.ds_tbs, 100))
await expectFail("device signature flipped", (x) => flip(x.dev_sig, 5))
await expectFail("device message changed (other transcript bytes)", (x) => flip(x.dev_msg, 40))
await expectFail("wrong digest entry", (x) => (x.digest_index = (x.digest_index + 1) % 18))
await expectFail("namespace public input = aamva", (x) => (x.name_space = "0x" + Buffer.from("org.iso.18013.5.1.aamva").toString("hex")))
await expectFail("doc type public input changed", (x) => (x.doc_type = "0x" + Buffer.from("org.iso.23220.photoid.1").toString("hex")))
await expectFail("deviceKey position moved", (x) => (x.device_key_pos += 1))
await expectFail("validUntil read from validFrom", (x) => (x.valid_until_pos = x.valid_from_pos))
await expectFail("transcript length off by one", (x) => (x.transcript_len -= 1))

const n2 = (await noir.execute(inputsOf(v2).inputs)).returnValue
const n3 = (await noir.execute(inputsOf(v3).inputs)).returnValue
if (n2 === n1) { pass++; console.log("ok   same licence re-issued (new IACA key, DS, MSO, device key, salts): same nullifier") } else { failures++; console.log("FAIL re-issued licence changed the nullifier") }
if (n3 !== n1) { pass++; console.log("ok   another document number: another nullifier") } else { failures++; console.log("FAIL two documents share a nullifier") }
console.log(`${pass} passed, ${failures} failed`)
process.exit(failures ? 1 : 0)
