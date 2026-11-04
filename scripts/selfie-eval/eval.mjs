#!/usr/bin/env node
// scripts/selfie-eval/eval.mjs: measure the selfie anchor's face pipeline
// on a folder of photos you are allowed to use.
//
//   node scripts/selfie-eval/eval.mjs --data <dir> [--out tmp/selfie-eval] [--model <face_landmarker.task>]
//
// <dir> holds one sub-folder per person with one or more photos each
// (jpg/png). For each photo it runs the web app's own code (lib/face/align.ts
// + the face-api descriptor, in headless Chrome), binarizes with
// lib/face/binarize.ts, and writes <out>/descriptors.json and
// <out>/templates.json. Then measure with the issuer's real fuzzy extractor:
//
//   SELFIE_EVAL_TEMPLATES=$PWD/<out>/templates.json \
//     go test -v -run TestEvalTemplates ./src/methods/fuzzy-extractor-selfie
//
// Needs app/web's node_modules (npm ci) and Chrome (CHROME env to override).
// The landmarker model defaults to app/web/public/face-models/ (run
// `npm run face-models` in app/web first). Photos never leave this machine.
import http from 'node:http';
import { readFileSync, readdirSync, writeFileSync, existsSync, mkdirSync, mkdtempSync, statSync } from 'node:fs';
import { join, extname, resolve, dirname } from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WEB = resolve(HERE, '../../app/web');
const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, arr) => (v.startsWith('--') ? [...a, [v.slice(2), arr[i + 1]]] : a), []));
if (!args.data) {
  console.error('usage: node scripts/selfie-eval/eval.mjs --data <dir-of-person-folders> [--out tmp/selfie-eval] [--model face_landmarker.task]');
  process.exit(2);
}
const DATA = resolve(args.data);
const OUT = resolve(args.out || 'tmp/selfie-eval');
const MODEL = resolve(args.model || join(WEB, 'public/face-models/face_landmarker.task'));
const NM = join(WEB, 'node_modules');
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
if (!existsSync(MODEL)) throw new Error(`landmarker model not found at ${MODEL}; run npm run face-models in app/web or pass --model`);
mkdirSync(join(OUT, 'lib'), { recursive: true });

// Compile the app's own face code so the page runs exactly what ships.
execFileSync(join(NM, '.bin/tsc'), [join(WEB, 'lib/face/align.ts'), join(WEB, 'lib/face/binarize.ts'),
  '--outDir', join(OUT, 'lib'), '--target', 'es2022', '--module', 'esnext', '--skipLibCheck'], { stdio: 'inherit' });

const list = [];
for (const person of readdirSync(DATA).sort()) {
  const dir = join(DATA, person);
  if (!statSync(dir).isDirectory()) continue;
  for (const f of readdirSync(dir).sort()) if (/\.(jpe?g|png)$/i.test(f) && !f.startsWith('.')) list.push({ person, path: `${person}/${f}` });
}
console.log(`${list.length} photos of ${new Set(list.map((l) => l.person)).size} people`);

const types = { '.js': 'text/javascript', '.mjs': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json', '.html': 'text/html', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png' };
let finish;
const finished = new Promise((r) => (finish = r));
const srv = http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split('?')[0]);
  if (req.method === 'POST') {
    let b = '';
    req.on('data', (d) => (b += d));
    req.on('end', () => { res.end('ok'); if (u === '/log') console.log('[page]', b); else finish(b); });
    return;
  }
  if (u === '/list') return res.end(JSON.stringify(list));
  // Serve only from the four roots, never outside them (no ../ escapes).
  const under = (root, rel) => { const p = resolve(root, rel); return p.startsWith(root + '/') ? p : null; };
  let p = null;
  if (u === '/') p = join(HERE, 'page.html');
  else if (u.startsWith('/nm/')) p = under(NM, u.slice(4));
  else if (u.startsWith('/data/')) p = under(DATA, u.slice(6));
  else if (u.startsWith('/lib/')) p = under(join(OUT, 'lib'), u.slice(5));
  else if (u === '/model/face_landmarker.task') p = MODEL;
  if (!p || !existsSync(p)) {
    res.statusCode = 404;
    return res.end();
  }
  res.setHeader('Content-Type', types[extname(p).toLowerCase()] || 'application/octet-stream');
  res.end(readFileSync(p));
}).listen(0, '127.0.0.1');
await new Promise((r) => srv.on('listening', r));
const chrome = spawn(CHROME, ['--headless=new', `--user-data-dir=${mkdtempSync(join(tmpdir(), 'selfie-eval-'))}`, '--no-first-run',
  '--enable-unsafe-swiftshader', `http://127.0.0.1:${srv.address().port}/`], { stdio: 'ignore' });
const body = await finished;
chrome.kill();
srv.close();

const results = JSON.parse(body);
const ok = results.filter((r) => r.descriptor);
for (const r of results.filter((r) => !r.descriptor)) console.log(`skipped ${r.path}: ${r.error}`);
writeFileSync(join(OUT, 'descriptors.json'), JSON.stringify(ok));

const { binarizeDescriptor, bytesToBase64 } = await import(pathToFileURL(join(OUT, 'lib/binarize.js')).href);
const templates = ok.map((r) => ({ person: r.person, path: r.path, template_b64: bytesToBase64(binarizeDescriptor(r.descriptor)) }));
writeFileSync(join(OUT, 'templates.json'), JSON.stringify(templates));

// Euclidean distance summary (dlib's usual same-person threshold is 0.6).
const dist = (a, b) => Math.sqrt(a.reduce((s, v, i) => s + (v - b[i]) ** 2, 0));
const g = [], im = [];
for (let i = 0; i < ok.length; i++) for (let j = i + 1; j < ok.length; j++) (ok[i].person === ok[j].person ? g : im).push(dist(ok[i].descriptor, ok[j].descriptor));
const stat = (a) => (a.length ? `n=${a.length} mean ${(a.reduce((s, v) => s + v, 0) / a.length).toFixed(3)} min ${Math.min(...a).toFixed(3)} max ${Math.max(...a).toFixed(3)}` : 'n=0');
console.log(`descriptor distance, same person: ${stat(g)}`);
console.log(`descriptor distance, different people: ${stat(im)}`);
console.log(`wrote ${join(OUT, 'templates.json')}; now run:\n  SELFIE_EVAL_TEMPLATES=${join(OUT, 'templates.json')} go test -v -run TestEvalTemplates ./src/methods/fuzzy-extractor-selfie`);
