#!/usr/bin/env node
// `next build` under `output: 'export'` (next.config.mjs) renders
// app/icon.tsx and app/apple-icon.tsx (next/og ImageResponse metadata
// routes) to out/icon and out/apple-icon — with NO file extension. That's a
// static-export quirk of these route conventions: the .png extension only
// shows up in the *served* URL's cache-busting query string
// (`/icon?<hash>`), not in the exported filename.
//
// app/manifest.ts's manifest.webmanifest correctly references /icon.png and
// /apple-icon.png (real browsers fetch a PWA manifest's icon `src` as a
// literal URL), and a static host like Firebase Hosting needs a real .png
// extension to infer the right Content-Type by default. So this runs right
// after `next build` (see package.json's "build" script) and copies each
// extensionless file to its expected .png-named twin. Idempotent, and a
// harmless no-op if a future Next.js version fixes this upstream and the
// extensionless source is simply absent.
import { copyFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const OUT_DIR = join(process.cwd(), 'out');
const PAIRS = [
  ['icon', 'icon.png'],
  ['apple-icon', 'apple-icon.png'],
];

for (const [from, to] of PAIRS) {
  const src = join(OUT_DIR, from);
  const dest = join(OUT_DIR, to);
  if (existsSync(src)) {
    copyFileSync(src, dest);
    console.log(`[fix-static-export-icons] wrote out/${to} from out/${from}`);
  } else {
    console.log(`[fix-static-export-icons] skipped out/${to}: out/${from} not found`);
  }
}
