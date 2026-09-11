// Client-side feature derivation for the fuzzy-extractor-selfie method
// (src/methods/fuzzy-extractor-selfie in the Go server).
//
// The server's `Method.CompleteCeremony` treats the submitted template as an
// OPAQUE, fixed-length, binarized biometric feature vector — TEMPLATE_BYTES
// (32) bytes, base64-encoded on the wire — and is completely agnostic to how
// the client produced it (see extractor.go's package doc: "the on-device
// biometric feature extraction ... [is] out of scope for this Go server
// module"). The server's own tests (RandomTemplateForTesting /
// NoisyTemplateForTesting in testsupport.go) stand in for a real reading with
// random bytes precisely because no real feature-extraction model lives in
// this repo.
//
// A production client would run a real on-device face-embedding + liveness
// model (explicitly flagged as future work in the round-4 session's
// wrapup). That is out of scope here too — this module is a deterministic,
// dependency-free placeholder that satisfies the SAME contract the server
// enforces (exactly TEMPLATE_BYTES bytes, tolerant of small pixel-level
// noise between two genuine captures of the same source image) using a
// well-known, inspectable technique: a grayscale "average hash" (aHash) over
// a small fixed grid. Two captures of the same physical scene produce
// templates that are IDENTICAL (or very close, well within the server's
// fuzzy-extractor Hamming-distance tolerance) bit-for-bit; two different
// images produce templates close to random relative to each other — the
// exact property Gen/Rep on the server needs to tell "same person, noisy
// reading" from "different person" apart. This is NOT a face-embedding model
// (it has no notion of facial features) and must not be presented as one; it
// exists to make the enroll/verify wiring in this app real and testable
// without requiring an ML dependency this session has no path to add.
//
// TEMPLATE_BYTES / GRID must stay in lockstep with the server's
// fuzzy-extractor-selfie.TemplateBytes constant (extractor.go): GRID*GRID
// bits packed into TEMPLATE_BYTES bytes.

/** Must equal src/methods/fuzzy-extractor-selfie's TemplateBytes constant. */
export const TEMPLATE_BYTES = 32;

/** GRID*GRID must equal TEMPLATE_BYTES*8 (256 bits -> 16x16). */
const GRID = 16;

/**
 * A minimal, DOM-independent stand-in for the browser's ImageData shape, so
 * deriveTemplateFromPixels is pure and unit-testable outside a browser/canvas
 * environment (no jsdom, no <canvas> polyfill needed).
 */
export type PixelBuffer = {
  width: number;
  height: number;
  /** RGBA, 4 bytes per pixel, row-major — the same layout as ImageData.data. */
  data: ArrayLike<number>;
};

/**
 * Derives a TEMPLATE_BYTES-byte binarized feature vector from a captured
 * image, via a 16x16 grayscale average hash:
 *
 *  1. Downsample to a GRID x GRID grid, box-averaging luminance per cell
 *     (cheap, and naturally smooths out single-pixel sensor noise).
 *  2. Threshold each of the GRID*GRID cells against the MEAN luminance over
 *     the whole grid (not a fixed constant — this is what makes the hash
 *     robust to overall brightness differences between two captures of the
 *     same scene under slightly different lighting).
 *  3. Pack the resulting GRID*GRID bits MSB-first into TEMPLATE_BYTES bytes.
 *
 * Deterministic: the same pixels always produce the same template. Throws if
 * img has zero width/height.
 */
export function deriveTemplateFromPixels(img: PixelBuffer): Uint8Array {
  if (img.width <= 0 || img.height <= 0) {
    throw new Error('deriveTemplateFromPixels: image has zero width or height');
  }
  const cells = downsampleGrayscale(img, GRID, GRID);
  const mean = cells.reduce((a, b) => a + b, 0) / cells.length;

  const bits = new Uint8Array(GRID * GRID);
  for (let i = 0; i < cells.length; i++) {
    bits[i] = cells[i] >= mean ? 1 : 0;
  }
  return packBits(bits, TEMPLATE_BYTES);
}

/**
 * Box-downsamples img's grayscale luminance to gridW x gridH cells
 * (row-major). Luminance uses the standard Rec. 601 weights; the alpha
 * channel is ignored (a selfie capture is always opaque).
 */
function downsampleGrayscale(img: PixelBuffer, gridW: number, gridH: number): number[] {
  const { width, height, data } = img;
  const out = new Array<number>(gridW * gridH).fill(0);
  const counts = new Array<number>(gridW * gridH).fill(0);

  for (let y = 0; y < height; y++) {
    const cellY = Math.min(gridH - 1, Math.floor((y * gridH) / height));
    for (let x = 0; x < width; x++) {
      const cellX = Math.min(gridW - 1, Math.floor((x * gridW) / width));
      const idx = (y * width + x) * 4;
      const r = data[idx] ?? 0;
      const g = data[idx + 1] ?? 0;
      const b = data[idx + 2] ?? 0;
      const lum = 0.299 * r + 0.587 * g + 0.114 * b;
      const cell = cellY * gridW + cellX;
      out[cell] += lum;
      counts[cell] += 1;
    }
  }
  for (let i = 0; i < out.length; i++) {
    out[i] = counts[i] > 0 ? out[i] / counts[i] : 0;
  }
  return out;
}

/** Packs bits (0/1 values, MSB-first) into an outBytes-length Uint8Array. */
function packBits(bits: ArrayLike<number>, outBytes: number): Uint8Array {
  const out = new Uint8Array(outBytes);
  for (let i = 0; i < bits.length; i++) {
    if (!bits[i]) continue;
    const byteIdx = Math.floor(i / 8);
    const bitIdx = 7 - (i % 8);
    if (byteIdx >= outBytes) continue; // extra bits beyond capacity are dropped
    out[byteIdx] |= 1 << bitIdx;
  }
  return out;
}

/** Base64-encodes bytes for the wire (template_b64 in the complete request). */
export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
