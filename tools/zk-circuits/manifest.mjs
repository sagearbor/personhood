// Package compiled circuits for document-chip-zk. Called by build.sh.
//
//   node manifest.mjs <compiled json dir> <dist dir> <issuer zk dir> <circuits commit> <variant path>...
//
// For every variant: gzip the artifact deterministically into <dist>, write
// its verification key (bb write_vk -t noir-recursive) into
// <issuer zk dir>/vks/<name>.vk, count its gates (bb gates), and record
// hashes. Then cut the SRS the largest circuit needs out of bb's CRS cache
// into <dist>/bn254_g1.dat, and write <issuer zk dir>/circuits.json.
import { execFileSync } from "child_process"
import { createHash } from "crypto"
import fs from "fs"
import os from "os"
import path from "path"
import zlib from "zlib"

const [jsonDir, dist, zkDir, commit, ...variants] = process.argv.slice(2)
const arch = `${os.arch() === "arm64" ? "arm64" : "amd64"}-${os.platform() === "darwin" ? "macos" : "linux"}`
const BB = process.env.BB ?? path.resolve(`node_modules/@aztec/bb.js/build/${arch}/bb`)
const TARGET = "noir-recursive"
const sha256 = (b) => createHash("sha256").update(b).digest("hex")

fs.mkdirSync(dist, { recursive: true })
fs.mkdirSync(path.join(zkDir, "vks"), { recursive: true })
const circuitsRoot = process.env.CIRCUITS_SRC

function packageName(dir) {
  const toml = fs.readFileSync(path.join(circuitsRoot, "src/noir", dir, "Nargo.toml"), "utf8")
  return toml.match(/^name\s*=\s*"([^"]+)"/m)[1]
}

const circuits = {}
let maxSize = 0
for (const v of variants) {
  const name = packageName(v)
  const src = path.join(jsonDir, `${name}.json`)
  const json = fs.readFileSync(src)
  // gzip with no name/mtime in the header, so the same input gives the same bytes
  const gz = zlib.gzipSync(json, { level: 9 })
  gz[4] = gz[5] = gz[6] = gz[7] = 0
  gz[9] = 0xff
  const file = `${name}.json.gz`
  fs.writeFileSync(path.join(dist, file), gz)

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "zkvk-"))
  execFileSync(BB, ["write_vk", "-t", TARGET, "-b", src, "-o", work], { stdio: "ignore" })
  const vk = fs.readFileSync(path.join(work, "vk"))
  fs.rmSync(work, { recursive: true, force: true })
  fs.writeFileSync(path.join(zkDir, "vks", `${name}.vk`), vk)

  const gatesOut = execFileSync(BB, ["gates", "-t", TARGET, "-b", src], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })
  const g = JSON.parse(gatesOut)
  const fn = (g.functions ?? [g])[0]
  const gates = Number(fn.circuit_size ?? fn.gates ?? 0)
  maxSize = Math.max(maxSize, gates)

  circuits[name] = {
    file,
    sha256: sha256(gz),
    bytes: gz.length,
    gates,
    vk_sha256: sha256(vk),
    license: v.includes("/ecdsa/") ? "unlicensed-dependency" : "clean",
    source: v,
  }
  console.log(`${name}: ${gates} gates, ${(gz.length / 1048576).toFixed(2)} MB`)
}

// SRS: the first 2^k G1 points, k = ceil(log2(largest circuit + a margin
// for the ZK masking rows)). bb keeps the points it downloaded in ~/.bb-crs.
let points = 1
while (points < maxSize + 1024) points *= 2
const crs = path.join(os.homedir(), ".bb-crs", "bn254_g1.dat")
const have = fs.existsSync(crs) ? fs.statSync(crs).size / 64 : 0
if (have < points) throw new Error(`${crs} has ${have} points, need ${points}: run bb prove on the largest circuit once so bb downloads them`)
const fd = fs.openSync(crs, "r")
const srs = Buffer.alloc(points * 64)
fs.readSync(fd, srs, 0, srs.length, 0)
fs.closeSync(fd)
fs.writeFileSync(path.join(dist, "bn254_g1.dat"), srs)

// A phone needs only the first 2^k points for its largest circuit, so the
// manifest pins the hash of every power-of-two prefix too: the wallet
// downloads just that prefix (HTTP Range) and checks it.
const prefixes = {}
for (let n = 1 << 17; n <= points; n *= 2) prefixes[n] = sha256(srs.subarray(0, n * 64))

const manifest = {
  version: 1,
  toolchain: { noir: "1.0.0-beta.22", bb: "5.0.0", circuits: process.env.CIRCUITS_LABEL ?? `zkpassport/circuits@${commit}`, verifier_target: TARGET },
  srs: { g1: { file: "bn254_g1.dat", sha256: sha256(srs), bytes: srs.length, points, prefix_sha256: prefixes } },
  circuits: Object.fromEntries(Object.keys(circuits).sort().map((k) => [k, circuits[k]])),
}
fs.writeFileSync(path.join(zkDir, "circuits.json"), JSON.stringify(manifest, null, 1) + "\n")
// Stale verification keys (variants dropped from the list) must not stay pinned.
for (const f of fs.readdirSync(path.join(zkDir, "vks"))) {
  if (f.endsWith(".vk") && !circuits[f.slice(0, -3)]) fs.rmSync(path.join(zkDir, "vks", f))
}
console.log(`${Object.keys(circuits).length} circuits; largest ${maxSize} gates; SRS ${points} points`)
