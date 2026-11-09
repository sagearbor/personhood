// Build the four zkPassport sub-circuit inputs from a real EF.DG1 + EF.SOD and
// the trusted CSCA PEM, then write them as JSON (target/<name>.inputs.json).
//
// Usage: npx tsx inputs.ts <vector dir with EF.DG1, EF.SOD, csca.pem> <country alpha3>
//
// The certificate packaging mirrors zkPassport's own test helper
// (src/ts/test-helper.ts, Apache-2.0), but takes the country from the caller so
// the ICAO specimen state "UTO" works.
import fs from "fs"
import path from "path"
import { AsnParser } from "@peculiar/asn1-schema"
import { Certificate as X509Certificate } from "@peculiar/asn1-x509"
import {
  Binary,
  PassportReader,
  createPackagedCertificatesFile,
  getDSCCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
  getExpiryDateCircuitInputs,
  packLeBytesAndHashPoseidon2,
  getSignatureAlgorithmType,
  getECDSAInfo,
  getRSAInfo,
  getKeySize,
  getAuthorityKeyId,
  getSubjectKeyId,
  OIDS_TO_PUBKEY_TYPE,
  type PackagedCertificate,
} from "@zkpassport/utils"

const [dir, country] = process.argv.slice(2)
const OUT = `target/${process.env.PROFILE ?? path.basename(dir)}`
if (!dir || !country) throw new Error("usage: tsx inputs.ts <vector dir> <alpha3>")

function pemToDer(pem: string): Uint8Array {
  return new Uint8Array(
    Buffer.from(pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""), "base64"),
  )
}

async function packageCsca(pem: string): Promise<PackagedCertificate> {
  const der = pemToDer(pem)
  const x509 = AsnParser.parse(der, X509Certificate)
  const fp = await packLeBytesAndHashPoseidon2(der)
  const v = x509.tbsCertificate.validity
  const common = {
    country,
    signature_algorithm: getSignatureAlgorithmType(x509),
    validity: {
      not_before: Math.floor(v.notBefore.getTime().getTime() / 1000),
      not_after: Math.floor(v.notAfter.getTime().getTime() / 1000),
    },
    authority_key_identifier: getAuthorityKeyId(x509),
    subject_key_identifier: getSubjectKeyId(x509),
    fingerprint: `0x${fp.toString(16).padStart(64, "0")}`,
  }
  const spki = x509.tbsCertificate.subjectPublicKeyInfo
  const t = (OIDS_TO_PUBKEY_TYPE as any)[spki.algorithm.algorithm] ?? spki.algorithm.algorithm
  if (t === "ecPublicKey") {
    const ec = getECDSAInfo(spki)
    const half = ec.publicKey.length / 2
    return {
      ...common,
      public_key: {
        type: "EC",
        curve: ec.curve,
        key_size: ec.keySize,
        public_key_x: `0x${Buffer.from(ec.publicKey.slice(1, half + 1)).toString("hex")}`,
        public_key_y: `0x${Buffer.from(ec.publicKey.slice(half + 1)).toString("hex")}`,
      },
    } as PackagedCertificate
  }
  const rsa = getRSAInfo(spki)
  return {
    ...common,
    public_key: {
      type: "RSA",
      modulus: `0x${rsa.modulus.toString(16)}`,
      exponent: Number(rsa.exponent),
      key_size: getKeySize(spki),
    },
  } as PackagedCertificate
}

const t0 = performance.now()
const reader = new PassportReader()
reader.loadPassport(
  Binary.from(fs.readFileSync(path.join(dir, "EF.DG1"))),
  Binary.from(fs.readFileSync(path.join(dir, "EF.SOD"))),
)
const passport = reader.getPassportViewModel() as any
// zkPassport maps the DSC issuer's alpha-2 country to alpha-3 with an ISO
// table. The ICAO specimen state Utopia ("UT"/"UTO") is not in it, so point
// the parsed view model (not the signed bytes) at the alpha-3 code. Real
// states map without this shim.
for (const k of ["issuer", "subject"]) {
  const tbs = passport.sod.certificate.tbs
  if (typeof tbs[k] === "string") tbs[k] = tbs[k].replace(/countryName=UT\b/, `countryName=${country}`)
}

const registry = await createPackagedCertificatesFile({
  certificates: [await packageCsca(fs.readFileSync(path.join(dir, "csca.pem"), "utf8"))],
  masterlists: [],
  timestamp: Math.floor(Date.UTC(2026, 10, 1) / 1000),
})

// Salts link the sub-proofs privately; in the wallet they are fresh random values.
const salts = { dg1Salt: 3n, expiryDateSalt: 3n, dg2HashSalt: 3n, privateNullifierSalt: 3n }
// Service scope = the issuer's domain separator (here a stand-in for
// Poseidon2("personhood:document-chip-zk")); subscope 0.
const SCOPE = BigInt(process.env.SCOPE ?? "0x706572736f6e686f6f64")
const now = Math.floor(Date.now() / 1000)

const out: Record<string, any> = {
  dsc: await getDSCCircuitInputs(passport, 1n, registry as any),
  id: await getIDDataCircuitInputs(passport, 1n, 2n),
  integrity: await getIntegrityCheckCircuitInputs(passport, 2n, salts),
  expiry: await getExpiryDateCircuitInputs(
    passport,
    // "expires on or after today": min_date is folded into the public param_commitment
    { expiry_date: { gte: new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate())) } } as any,
    salts,
    0n,
    SCOPE,
    0n,
    now,
  ),
}
fs.mkdirSync(OUT, { recursive: true })
for (const [k, v] of Object.entries(out)) {
  if (!v) throw new Error(`no inputs for ${k}`)
  fs.writeFileSync(`${OUT}/${k}.inputs.json`, JSON.stringify(v, (_, x) => (typeof x === "bigint" ? `0x${x.toString(16)}` : x)))
}
fs.writeFileSync(`${OUT}/registry.json`, JSON.stringify({ root: registry.root, timestamp: registry.timestamp }))
console.log(`inputs built in ${((performance.now() - t0) / 1000).toFixed(2)} s; registry root ${registry.root}`)
