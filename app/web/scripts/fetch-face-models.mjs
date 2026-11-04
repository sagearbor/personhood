#!/usr/bin/env node
// Puts the selfie anchor's on-device face models into public/face-models/,
// so the app serves them itself and never loads code or weights from a CDN
// at runtime. Run by `npm run build` (and `npm run face-models`).
//
// - MediaPipe Tasks Vision WASM runtime: copied from node_modules
//   (@mediapipe/tasks-vision, version pinned in package.json, Apache-2.0).
// - dlib face-recognition ResNet weights (public domain, ported to tfjs by
//   @vladmandic/face-api, MIT): copied from node_modules.
// - MediaPipe Face Landmarker model (Apache-2.0): not on npm, so downloaded
//   once from Google's model bucket and checked against a pinned SHA-256.
//   An existing file with the right hash is reused (offline builds work).
//
// public/face-models/ is gitignored; nothing here is committed.
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const WEB = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(WEB, 'public/face-models');
const NM = join(WEB, 'node_modules');

const LANDMARKER_URL = 'https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task';
const LANDMARKER_SHA256 = '64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff';

const COPIES = [
  ['@mediapipe/tasks-vision/wasm/vision_wasm_internal.js', 'wasm/vision_wasm_internal.js'],
  ['@mediapipe/tasks-vision/wasm/vision_wasm_internal.wasm', 'wasm/vision_wasm_internal.wasm'],
  ['@mediapipe/tasks-vision/wasm/vision_wasm_nosimd_internal.js', 'wasm/vision_wasm_nosimd_internal.js'],
  ['@mediapipe/tasks-vision/wasm/vision_wasm_nosimd_internal.wasm', 'wasm/vision_wasm_nosimd_internal.wasm'],
  ['@vladmandic/face-api/model/face_recognition_model-weights_manifest.json', 'face_recognition_model-weights_manifest.json'],
  ['@vladmandic/face-api/model/face_recognition_model.bin', 'face_recognition_model.bin'],
];

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

mkdirSync(join(OUT, 'wasm'), { recursive: true });
for (const [from, to] of COPIES) {
  const src = join(NM, from);
  if (!existsSync(src)) throw new Error(`fetch-face-models: ${src} missing; run npm ci`);
  copyFileSync(src, join(OUT, to));
}

const task = join(OUT, 'face_landmarker.task');
if (!existsSync(task) || sha256(readFileSync(task)) !== LANDMARKER_SHA256) {
  const res = await fetch(LANDMARKER_URL);
  if (!res.ok) throw new Error(`fetch-face-models: GET ${LANDMARKER_URL}: ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const got = sha256(buf);
  if (got !== LANDMARKER_SHA256) throw new Error(`fetch-face-models: face_landmarker.task sha256 ${got}, want ${LANDMARKER_SHA256}`);
  writeFileSync(task, buf);
}
console.log(`fetch-face-models: ${OUT} ready`);
