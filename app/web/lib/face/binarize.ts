// Turns a face descriptor (128 floats from dlib's face-recognition ResNet)
// into the 32-byte template the issuer's fuzzy extractor takes.
//
// Method: subtract a population mean, then take the sign of 256 fixed
// random +-1 projections (SimHash). Two descriptors that are close in angle
// give templates that differ in few bits; unrelated faces differ in about
// half of them. Without the mean subtraction every dlib descriptor shares a
// large common component and unrelated faces land only ~18% apart in bits,
// which the issuer's fuzzy extractor would read as "same person".
//
// Only the 32-byte template leaves the phone. The descriptor and the photo
// stay on the device.
//
// Measured numbers and how to reproduce them: docs/selfie-anchor.md.

/** Must equal src/methods/fuzzy-extractor-selfie's TemplateBytes. */
export const TEMPLATE_BYTES = 32;
export const DESCRIPTOR_DIM = 128;
const TEMPLATE_BITS = TEMPLATE_BYTES * 8;

/**
 * Mean descriptor of the 204 frontal photos (102 adults, neutral + smiling)
 * of the Face Research Lab London Set (DeBruine & Jones 2017, CC BY 4.0,
 * doi:10.6084/m9.figshare.5047666), computed through this app's own
 * alignment (lib/face/align.ts). Changing it, the projection seed or the
 * alignment changes every template, so everyone enrolled before would
 * enroll again as a new person: version it, never edit it in place.
 */
export const POPULATION_MEAN_V1: readonly number[] = [
  -0.1326, 0.0956, 0.0673, -0.0384, -0.1027, -0.0242, -0.0336, -0.0720, 0.1947, -0.0849, 0.2025, 
  -0.0267, -0.2398, -0.0227, -0.0136, 0.1401, -0.1798, -0.1620, -0.0954, -0.0725, 0.0366, 0.0313, 
  -0.0177, 0.0674, -0.1620, -0.2907, -0.0695, -0.1232, 0.0310, -0.1254, -0.0247, 0.0236, -0.1752, 
  -0.0464, 0.0204, 0.0602, -0.0388, -0.0911, 0.1972, 0.0286, -0.2119, -0.0204, 0.0239, 0.2679, 
  0.2092, 0.0009, 0.0109, -0.0636, 0.1247, -0.3089, 0.0304, 0.1830, 0.0760, 0.0833, 0.0851, 
  -0.1573, 0.0061, 0.1329, -0.1833, 0.0750, 0.0702, -0.0916, -0.0369, -0.0654, 0.2057, 0.1067, 
  -0.1259, -0.1505, 0.1672, -0.1625, -0.0711, 0.1215, -0.0984, -0.2059, -0.2646, 0.0453, 0.4360, 
  0.1541, -0.1748, 0.0376, -0.0971, -0.0340, 0.0296, 0.0902, -0.0459, 0.0037, -0.0874, 0.0157, 
  0.2198, 0.0011, 0.0092, 0.2452, 0.0066, -0.0076, 0.0297, 0.0470, -0.0874, -0.0401, -0.0984, 
  -0.0306, 0.0208, -0.0708, -0.0097, 0.0973, -0.1813, 0.1530, -0.0121, -0.0277, -0.0458, -0.0178, 
  -0.0685, -0.0053, 0.1674, -0.2827, 0.1757, 0.1735, 0.0386, 0.1349, 0.0326, 0.0505, -0.0088, 
  -0.0368, -0.1472, -0.0807, 0.0318, -0.0413, 0.0110, 0.0182
];

/** Seed of the projection matrix. Part of the template version, like the mean. */
const PROJECTION_SEED = 0x5e1f1e01;

/** The template version this code produces; sent to the issuer. */
export const TEMPLATE_VERSION = 'dlib128-simhash256-v1';

let projection: Int8Array | null = null;

/**
 * 256 x 128 matrix of +1/-1 from xorshift32. Integer-only, so every
 * JavaScript engine builds exactly the same matrix.
 */
function projectionMatrix(): Int8Array {
  if (projection) return projection;
  const m = new Int8Array(TEMPLATE_BITS * DESCRIPTOR_DIM);
  let s = PROJECTION_SEED >>> 0;
  for (let i = 0; i < m.length; i++) {
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5; s >>>= 0;
    m[i] = s & 1 ? 1 : -1;
  }
  projection = m;
  return m;
}

/** Element-wise mean of several descriptors (several frames of one face). */
export function averageDescriptors(ds: readonly ArrayLike<number>[]): Float64Array {
  if (ds.length === 0) throw new Error('averageDescriptors: no descriptors');
  const out = new Float64Array(DESCRIPTOR_DIM);
  for (const d of ds) {
    if (d.length !== DESCRIPTOR_DIM) throw new Error(`descriptor must have ${DESCRIPTOR_DIM} values, got ${d.length}`);
    for (let i = 0; i < DESCRIPTOR_DIM; i++) out[i] += d[i];
  }
  for (let i = 0; i < DESCRIPTOR_DIM; i++) out[i] /= ds.length;
  return out;
}

/** SimHash of (descriptor - mean), packed MSB-first into TEMPLATE_BYTES. */
export function binarizeDescriptor(
  descriptor: ArrayLike<number>,
  mean: readonly number[] = POPULATION_MEAN_V1,
): Uint8Array {
  if (descriptor.length !== DESCRIPTOR_DIM) {
    throw new Error(`descriptor must have ${DESCRIPTOR_DIM} values, got ${descriptor.length}`);
  }
  const p = projectionMatrix();
  const centered = new Float64Array(DESCRIPTOR_DIM);
  for (let i = 0; i < DESCRIPTOR_DIM; i++) centered[i] = descriptor[i] - mean[i];
  const out = new Uint8Array(TEMPLATE_BYTES);
  for (let bit = 0; bit < TEMPLATE_BITS; bit++) {
    let dot = 0;
    const row = bit * DESCRIPTOR_DIM;
    for (let i = 0; i < DESCRIPTOR_DIM; i++) dot += p[row + i] * centered[i];
    if (dot > 0) out[bit >> 3] |= 0x80 >> (bit & 7);
  }
  return out;
}

/** Number of differing bits between two templates. */
export function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  let d = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    let x = a[i] ^ b[i];
    while (x) { d++; x &= x - 1; }
  }
  return d;
}

/** Base64 for the wire (template_b64). */
export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
