// Turn an ISO/IEC 18013-5 DeviceResponse (as the phone's wallet returns it
// to the app, decrypted on the phone) into the private inputs of personhood's
// mobile-id-zk circuit (tools/zk-circuits/mdoc). Pure TypeScript, no
// dependencies: the same file runs in the spike (Node) and in the OpenLine
// wallet (React Native). Apache-2.0.
//
// Nothing here leaves the phone: the output is the circuit witness input.

export type Bytes = Uint8Array

// ------------------------------------------------------------ CBOR

export interface Node {
  major: number
  start: number // first byte of the head
  headLen: number
  arg: number // length / value / tag number
  end: number // one past the item
  value?: Bytes | string | number | boolean | null
  items?: Node[] // array elements
  entries?: [Node, Node][] // map entries, in wire order
  tagged?: Node
}

export class MdocError extends Error {
  reason: string
  constructor(reason: string, message: string) {
    super(message)
    this.reason = reason
  }
}

function fail(reason: string, msg: string): never {
  throw new MdocError(reason, msg)
}

export function decode(b: Bytes, pos = 0, depth = 0): Node {
  if (depth > 24 || pos >= b.length) fail("mdoc_malformed", "CBOR: truncated")
  const start = pos
  const major = b[pos] >> 5
  const info = b[pos] & 0x1f
  pos++
  let arg = 0
  if (info < 24) arg = info
  else if (info <= 27) {
    const size = 1 << (info - 24)
    if (pos + size > b.length) fail("mdoc_malformed", "CBOR: truncated head")
    for (let i = 0; i < size; i++) arg = arg * 256 + b[pos + i]
    pos += size
  } else fail("mdoc_malformed", "CBOR: indefinite length")
  const headLen = pos - start
  const node: Node = { major, start, headLen, arg, end: pos }
  switch (major) {
    case 0:
      node.value = arg
      break
    case 1:
      node.value = -1 - arg
      break
    case 2:
    case 3:
      if (pos + arg > b.length) fail("mdoc_malformed", "CBOR: truncated string")
      node.value = major === 2 ? b.subarray(pos, pos + arg) : utf8(b.subarray(pos, pos + arg))
      node.end = pos + arg
      break
    case 4:
      node.items = []
      for (let i = 0; i < arg; i++) {
        const c = decode(b, pos, depth + 1)
        node.items.push(c)
        pos = c.end
      }
      node.end = pos
      break
    case 5:
      node.entries = []
      for (let i = 0; i < arg; i++) {
        const k = decode(b, pos, depth + 1)
        const v = decode(b, k.end, depth + 1)
        node.entries.push([k, v])
        pos = v.end
      }
      node.end = pos
      break
    case 6:
      node.tagged = decode(b, pos, depth + 1)
      node.end = node.tagged.end
      break
    default:
      if (info === 20) node.value = false
      else if (info === 21) node.value = true
      else if (info === 22) node.value = null
      else fail("mdoc_malformed", "CBOR: float or simple value")
  }
  return node
}

function utf8(b: Bytes): string {
  let s = ""
  for (const c of b) s += String.fromCharCode(c)
  try {
    return decodeURIComponent(escape(s))
  } catch {
    return s
  }
}

export function get(m: Node, key: string | number): Node | undefined {
  if (!m.entries) return undefined
  for (const [k, v] of m.entries) if (k.value === key) return v
  return undefined
}

function must(n: Node | undefined, what: string): Node {
  if (!n) fail("mdoc_malformed", `missing ${what}`)
  return n
}

export function head(major: number, n: number): number[] {
  const m = major << 5
  if (n < 24) return [m | n]
  if (n < 256) return [m | 24, n]
  if (n < 65536) return [m | 25, n >> 8, n & 0xff]
  return [m | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
}

export function concat(...parts: (Bytes | number[])[]): Bytes {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export const ascii = (s: string): Bytes => Uint8Array.from(s, (c) => c.charCodeAt(0))
export const bstr = (b: Bytes): Bytes => concat(head(2, b.length), b)
export const tstr = (s: string): Bytes => concat(head(3, s.length), ascii(s))

/** COSE Sig_structure ["Signature1", protected, h'', payload]. */
export function sigStructure(protectedHdr: Bytes, payload: Bytes): Bytes {
  return concat([0x84], tstr("Signature1"), bstr(protectedHdr), [0x40], bstr(payload))
}

// ------------------------------------------------------------ DER / ECDSA

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n

function toBig(b: Bytes): bigint {
  let x = 0n
  for (const c of b) x = (x << 8n) | BigInt(c)
  return x
}

function fromBig(x: bigint, len: number): Bytes {
  const out = new Uint8Array(len)
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return out
}

/** r||s with s normalised to the low half (the circuit's black box needs it). */
export function lowS(sig: Bytes): Bytes {
  if (sig.length !== 64) fail("mdoc_unsupported", "signature is not a P-256 r||s")
  let s = toBig(sig.subarray(32))
  if (s > P256_N / 2n) s = P256_N - s
  return concat(sig.subarray(0, 32), fromBig(s, 32))
}

function derHeader(b: Bytes, pos: number): { tag: number; hl: number; len: number } {
  const tag = b[pos]
  const l = b[pos + 1]
  if (l < 0x80) return { tag, hl: 2, len: l }
  if (l === 0x81) return { tag, hl: 3, len: b[pos + 2] }
  if (l === 0x82) return { tag, hl: 4, len: (b[pos + 2] << 8) | b[pos + 3] }
  fail("mdoc_unsupported", "DER length too large")
}

/** A certificate's TBSCertificate bytes and its ECDSA signature as r||s. */
export function splitCertificate(der: Bytes): { tbs: Bytes; sig: Bytes; sigAlg: Bytes } {
  const outer = derHeader(der, 0)
  let p = outer.hl
  const t = derHeader(der, p)
  const tbs = der.subarray(p, p + t.hl + t.len)
  p += t.hl + t.len
  const a = derHeader(der, p)
  const sigAlg = der.subarray(p + a.hl, p + a.hl + a.len)
  p += a.hl + a.len
  const bs = derHeader(der, p)
  if (bs.tag !== 0x03) fail("mdoc_malformed", "certificate signature")
  const ecdsa = der.subarray(p + bs.hl + 1, p + bs.hl + bs.len) // skip unused-bits byte
  const seq = derHeader(ecdsa, 0)
  let q = seq.hl
  const ints: Bytes[] = []
  for (let i = 0; i < 2; i++) {
    const h = derHeader(ecdsa, q)
    let v = ecdsa.subarray(q + h.hl, q + h.hl + h.len)
    while (v.length > 32 && v[0] === 0) v = v.subarray(1)
    if (v.length > 32) fail("mdoc_unsupported", "certificate signature is not P-256")
    ints.push(concat(new Uint8Array(32 - v.length), v))
    q += h.hl + h.len
  }
  return { tbs, sig: lowS(concat(ints[0], ints[1])), sigAlg }
}

// ecdsa-with-SHA256
const ECDSA_SHA256 = Uint8Array.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])
// SubjectPublicKeyInfo prefix of an uncompressed P-256 key.
const SPKI_P256 = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
  0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
])

function indexOf(hay: Bytes, needle: Bytes, from = 0): number {
  outer: for (let i = from; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer
    return i
  }
  return -1
}

/** The P-256 public key (x, y) of a certificate, or null for another key type. */
export function certificateP256Key(der: Bytes): { x: Bytes; y: Bytes } | null {
  const i = indexOf(der, SPKI_P256)
  if (i < 0) return null
  return { x: der.slice(i + 27, i + 59), y: der.slice(i + 59, i + 91) }
}

// ------------------------------------------------------------ the mdoc

export const DOC_TYPE_MDL = "org.iso.18013.5.1.mDL"
export const NAME_SPACE_MDL = "org.iso.18013.5.1"
/** Credentials a company (Apple, Google), not a government, signs: refused. */
export const COMPANY_SIGNED_DOC_TYPES = ["org.iso.23220.photoid.1", "com.google.wallet.idcard.1"]

export interface ParsedMdoc {
  docType: string
  dsCert: Bytes
  /** Issuer Sig_structure and the DS signature over it. */
  issuerMsg: Bytes
  issuerSig: Bytes
  msoStart: number // in issuerMsg
  msoEnd: number
  mso: Node
  deviceProtected: Bytes
  deviceSig: Bytes
  deviceNameSpacesBytes: Bytes
  /** IssuerSignedItemBytes per namespace / element. */
  items: Map<string, Map<string, Bytes>>
  validFrom: string
  validUntil: string
  deviceKey: { x: Bytes; y: Bytes }
}

export function parseDeviceResponse(resp: Bytes): ParsedMdoc {
  const root = decode(resp)
  if (root.end !== resp.length) fail("mdoc_malformed", "trailing bytes")
  const docs = must(get(root, "documents"), "documents").items ?? []
  if (docs.length !== 1) fail("mdoc_malformed", `expected one document, got ${docs.length}`)
  const doc = docs[0]
  const docType = must(get(doc, "docType"), "docType").value as string
  if (COMPANY_SIGNED_DOC_TYPES.includes(docType)) fail("mdoc_company_signed", `${docType} is signed by the wallet's company, not a government`)
  const issuerSigned = must(get(doc, "issuerSigned"), "issuerSigned")
  const auth = must(get(issuerSigned, "issuerAuth"), "issuerAuth").items ?? []
  if (auth.length !== 4) fail("mdoc_malformed", "issuerAuth is not COSE_Sign1")
  const protectedHdr = auth[0].value as Bytes
  const x5 = must(get(auth[1], 33), "x5chain")
  const dsCert = (x5.items ? x5.items[0].value : x5.value) as Bytes
  const payload = auth[2].value as Bytes
  const issuerMsg = sigStructure(protectedHdr, payload)
  const issuerSig = lowS(auth[3].value as Bytes)
  // payload = #6.24(bstr MSO)
  const tag = decode(payload)
  if (tag.major !== 6 || tag.arg !== 24 || !tag.tagged || tag.tagged.major !== 2) fail("mdoc_malformed", "MSO is not embedded CBOR")
  const payloadOffset = issuerMsg.length - payload.length
  const msoStart = payloadOffset + tag.tagged.start + tag.tagged.headLen
  const msoEnd = issuerMsg.length
  const mso = decode(issuerMsg, msoStart)
  if (mso.end !== msoEnd) fail("mdoc_malformed", "MSO length")
  if (get(mso, "digestAlgorithm")?.value !== "SHA-256") fail("mdoc_unsupported", "MSO digest algorithm is not SHA-256")
  if (get(mso, "docType")?.value !== docType) fail("mdoc_malformed", "MSO docType differs")

  const vi = must(get(mso, "validityInfo"), "validityInfo")
  const date = (n: Node | undefined, what: string): string => {
    const s = must(n, what).tagged?.value
    if (typeof s !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(s)) fail("mdoc_unsupported", `${what} is not a plain UTC tdate`)
    return s
  }
  const validFrom = date(get(vi, "validFrom"), "validFrom")
  const validUntil = date(get(vi, "validUntil"), "validUntil")

  const dk = must(get(must(get(mso, "deviceKeyInfo"), "deviceKeyInfo"), "deviceKey"), "deviceKey")
  const want = Uint8Array.from([0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20])
  const dkb = issuerMsg.subarray(dk.start, dk.end)
  if (dkb.length !== 75 || indexOf(dkb, want) !== 0 || dkb[40] !== 0x22) fail("mdoc_unsupported", "device key is not a plain P-256 COSE_Key")
  const deviceKey = { x: dkb.slice(8, 40), y: dkb.slice(43, 75) }

  const items = new Map<string, Map<string, Bytes>>()
  const nss = must(get(issuerSigned, "nameSpaces"), "nameSpaces")
  for (const [k, v] of nss.entries ?? []) {
    const m = new Map<string, Bytes>()
    for (const it of v.items ?? []) {
      const raw = resp.subarray(it.start, it.end)
      const inner = it.tagged ? decode(it.tagged.value as Bytes) : undefined
      const id = inner && get(inner, "elementIdentifier")?.value
      if (typeof id === "string") m.set(id, raw)
    }
    items.set(k.value as string, m)
  }

  const deviceSigned = must(get(doc, "deviceSigned"), "deviceSigned")
  const dns = must(get(deviceSigned, "nameSpaces"), "deviceSigned.nameSpaces")
  const deviceNameSpacesBytes = resp.slice(dns.start, dns.end)
  const ds = get(must(get(deviceSigned, "deviceAuth"), "deviceAuth"), "deviceSignature")
  if (!ds) fail("mdoc_unsupported", "the wallet answered with a device MAC, not a device signature")
  const dsItems = ds.items ?? []
  return {
    docType,
    dsCert,
    issuerMsg,
    issuerSig,
    msoStart,
    msoEnd,
    mso,
    deviceProtected: dsItems[0].value as Bytes,
    deviceSig: lowS(dsItems[3].value as Bytes),
    deviceNameSpacesBytes,
    items,
    validFrom,
    validUntil,
    deviceKey,
  }
}

/** The bytes the device key signed, for a session transcript. */
export function deviceMessage(p: ParsedMdoc, sessionTranscript: Bytes): Bytes {
  const da = concat([0x84], tstr("DeviceAuthentication"), sessionTranscript, tstr(p.docType), p.deviceNameSpacesBytes)
  const daBytes = concat([0xd8, 0x18], bstr(da))
  return sigStructure(p.deviceProtected, daBytes)
}

// ------------------------------------------------------------ circuit inputs

export const LIMITS = { TBS: 1024, ITEM: 192, DEV: 448, T: 256, E: 64 }

export function circuitFor(issuerMsgLen: number, available: number[]): number | null {
  const sizes = [...available].sort((a, b) => a - b)
  for (const s of sizes) if (issuerMsgLen <= s - 4) return s
  return null
}

const pad = (b: Bytes, n: number): number[] => {
  if (b.length > n) fail("mdoc_unsupported", `field of ${b.length} bytes exceeds ${n}`)
  const out = new Array<number>(n).fill(0)
  b.forEach((c, i) => (out[i] = c))
  return out
}

export const hex = (b: Bytes): string => "0x" + Array.from(b, (c) => c.toString(16).padStart(2, "0")).join("")

/** Big-endian pack of at most 31 bytes as a field (hex). */
export function packBE(b: Bytes): string {
  if (b.length > 31) fail("mdoc_unsupported", "value longer than 31 bytes")
  return "0x" + toBig(b).toString(16)
}

export interface RegistryEntry {
  jurisdiction: string // e.g. "US-CA"
  x: Bytes
  y: Bytes
  index: number
  path: string[] // 16 sibling hashes, hex
}

export interface Session {
  registryRoot: string // hex field
  scope: string // hex field
  now: string // "YYYY-MM-DDTHH:MM:SSZ"
  sessionTranscript: Bytes
  transcriptHash: Bytes // SHA-256(sessionTranscript)
}

/** The full input object for mdoc_p256_msg_<msgSize>. */
export function buildInputs(p: ParsedMdoc, iaca: RegistryEntry, s: Session, msgSize: number, nameSpace = NAME_SPACE_MDL) {
  const { tbs, sig: dsSig } = splitCertificate(p.dsCert)
  const sigAlg = splitCertificate(p.dsCert).sigAlg
  if (indexOf(sigAlg, ECDSA_SHA256) !== 0) fail("mdoc_unsupported", "document signer certificate is not ecdsa-with-SHA256")
  if (!certificateP256Key(p.dsCert)) fail("mdoc_unsupported", "document signer key is not P-256")
  // Position of a key's text head in issuerMsg: an MSO key, or a key one map down.
  const pos = (key: string): number => {
    for (const [k] of p.mso.entries ?? []) if (k.value === key) return k.start
    for (const [, v] of p.mso.entries ?? [])
      for (const [k2] of v.entries ?? []) if (k2.value === key) return k2.start
    return fail("mdoc_malformed", `MSO has no ${key}`)
  }
  const vd = must(get(p.mso, "valueDigests"), "valueDigests")
  let nsKey: Node | undefined
  let nsMap: Node | undefined
  for (const [k, v] of vd.entries ?? [])
    if (k.value === nameSpace) {
      nsKey = k
      nsMap = v
    }
  if (!nsKey || !nsMap) fail("mdoc_missing_element", `MSO has no ${nameSpace} digests`)
  const item = p.items.get(nameSpace)?.get("document_number")
  if (!item) fail("mdoc_missing_element", "the wallet did not share document_number")
  const inner = decode(decode(item).tagged!.value as Bytes)
  const digestID = get(inner, "digestID")?.value
  const value = get(inner, "elementValue")?.value
  if (typeof value !== "string" || value.length < 1 || ascii(value).length > 31) fail("mdoc_unsupported", "document_number is not a short text")
  const digestIndex = (nsMap.entries ?? []).findIndex(([k]) => k.value === digestID)
  if (digestIndex < 0) fail("mdoc_malformed", "document_number digest not in the MSO")
  if ((nsMap.entries ?? []).length > LIMITS.E) fail("mdoc_unsupported", "too many digests in the namespace")
  const dev = deviceMessage(p, s.sessionTranscript)
  if (s.sessionTranscript.length > LIMITS.T) fail("mdoc_unsupported", "session transcript too long")
  if (tbs.length > LIMITS.TBS - 4 || item.length > LIMITS.ITEM - 4 || dev.length > LIMITS.DEV - 4) fail("mdoc_unsupported", "a field is too long for the circuit")
  if (p.issuerMsg.length > msgSize - 4) fail("mdoc_unsupported", "MSO too long for the circuit")
  const ser = (b: Bytes) => Array.from(b)
  return {
    registry_root: s.registryRoot,
    now: packBE(ascii(s.now)),
    doc_type: packBE(ascii(p.docType)),
    name_space: packBE(ascii(nameSpace)),
    transcript_hash_hi: hex(s.transcriptHash.subarray(0, 16)),
    transcript_hash_lo: hex(s.transcriptHash.subarray(16)),
    scope: s.scope,
    jurisdiction: packBE(ascii(iaca.jurisdiction)),
    iaca_x: ser(iaca.x),
    iaca_y: ser(iaca.y),
    leaf_index: iaca.index,
    leaf_path: iaca.path,
    ds_tbs: pad(tbs, LIMITS.TBS),
    ds_tbs_len: tbs.length,
    ds_sig: ser(dsSig),
    issuer_msg: pad(p.issuerMsg, msgSize),
    issuer_msg_len: p.issuerMsg.length,
    issuer_sig: ser(p.issuerSig),
    doc_type_pos: pos("docType"),
    device_key_pos: pos("deviceKey"),
    valid_from_pos: pos("validFrom"),
    valid_until_pos: pos("validUntil"),
    name_space_pos: nsKey.start,
    digest_index: digestIndex,
    item: pad(item, LIMITS.ITEM),
    item_len: item.length,
    dev_msg: pad(dev, LIMITS.DEV),
    dev_msg_len: dev.length,
    dev_sig: ser(p.deviceSig),
    transcript_len: s.sessionTranscript.length,
  }
}
