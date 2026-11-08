// Compile zkPassport circuit variants with noir_wasm (pinned in package.json)
// and write deterministic, stripped artifacts. Called by build.sh.
//
//   node compile.mjs <circuits checkout> <out dir> <variant path>...
//
// Each artifact keeps only what proving needs ({noir_version, hash, abi,
// bytecode}; no debug symbols or source file map) and is written as
// <name>.json, where <name> is the Nargo package name.
import { compile, createFileManager } from "@noir-lang/noir_wasm"
import fs from "fs"
import path from "path"

const [repo, outDir, ...variants] = process.argv.slice(2)
if (!repo || !outDir || variants.length === 0) throw new Error("usage: node compile.mjs <circuits> <out> <variant>...")
const root = path.resolve(repo, "src/noir")
fs.mkdirSync(outDir, { recursive: true })

function packageName(dir) {
  const toml = fs.readFileSync(path.join(root, dir, "Nargo.toml"), "utf8")
  const m = toml.match(/^name\s*=\s*"([^"]+)"/m)
  if (!m) throw new Error(`no package name in ${dir}/Nargo.toml`)
  return m[1]
}

const silent = () => {}
for (const v of variants) {
  const name = packageName(v)
  const out = path.join(outDir, `${name}.json`)
  if (fs.existsSync(out)) {
    console.log(`${name}: cached`)
    continue
  }
  const t0 = performance.now()
  const res = await compile(createFileManager(root), path.join(root, v), silent, silent)
  const p = res.program ?? res
  const stripped = { noir_version: p.noir_version, hash: p.hash, abi: p.abi, bytecode: p.bytecode }
  fs.writeFileSync(out + ".tmp", JSON.stringify(stripped))
  fs.renameSync(out + ".tmp", out)
  console.log(`${name}: compiled in ${((performance.now() - t0) / 1000).toFixed(1)} s`)
}
