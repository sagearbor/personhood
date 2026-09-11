import { defineConfig } from 'vitest/config';
import path from 'node:path';

// Unit tests only (lib/*.test.ts) — pure TS/JS logic that doesn't need a
// DOM/browser environment, matching this repo's Go-side convention of
// dependency-light, fast unit tests. Real browser behavior (camera capture,
// actual enroll/verify HTTP calls against a running server) is covered by
// the headless-browser verification run documented in the fuzzy-extractor-
// selfie web-wiring session's wrapup, not by this suite.
export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  test: {
    include: ['**/*.test.ts'],
    environment: 'node',
  },
});
