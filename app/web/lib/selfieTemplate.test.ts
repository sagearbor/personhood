import { describe, expect, it } from 'vitest';
import { TEMPLATE_BYTES, bytesToBase64, deriveTemplateFromPixels, type PixelBuffer } from './selfieTemplate';

function solidImage(width: number, height: number, rgba: [number, number, number, number]): PixelBuffer {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    data[i * 4] = rgba[0];
    data[i * 4 + 1] = rgba[1];
    data[i * 4 + 2] = rgba[2];
    data[i * 4 + 3] = rgba[3];
  }
  return { width, height, data };
}

/** A deterministic pseudo-photo: per-pixel luminance from a simple LCG seeded
 * by `seed`, so tests can construct reproducible "noisy but similar" and
 * "unrelated" images without any real image fixture. */
function pseudoPhoto(width: number, height: number, seed: number): PixelBuffer {
  const data = new Uint8ClampedArray(width * height * 4);
  let s = seed >>> 0;
  const next = () => {
    // Numerical Recipes LCG constants — fine for deterministic test fixtures,
    // not for anything security-sensitive.
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s;
  };
  for (let i = 0; i < width * height; i++) {
    const v = next() & 0xff;
    data[i * 4] = v;
    data[i * 4 + 1] = v;
    data[i * 4 + 2] = v;
    data[i * 4 + 3] = 255;
  }
  return { width, height, data };
}

function flipPixels(img: PixelBuffer, count: number): PixelBuffer {
  const data = new Uint8ClampedArray(img.data as Uint8ClampedArray);
  for (let i = 0; i < count; i++) {
    const idx = i * 4;
    data[idx] = 255 - data[idx];
    data[idx + 1] = 255 - data[idx + 1];
    data[idx + 2] = 255 - data[idx + 2];
  }
  return { width: img.width, height: img.height, data };
}

function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  let dist = 0;
  for (let i = 0; i < a.length; i++) {
    let x = a[i] ^ b[i];
    while (x) {
      dist += x & 1;
      x >>= 1;
    }
  }
  return dist;
}

describe('deriveTemplateFromPixels', () => {
  it('produces exactly TEMPLATE_BYTES bytes', () => {
    const img = solidImage(64, 64, [128, 128, 128, 255]);
    const template = deriveTemplateFromPixels(img);
    expect(template).toBeInstanceOf(Uint8Array);
    expect(template.length).toBe(TEMPLATE_BYTES);
    expect(TEMPLATE_BYTES).toBe(32); // must match src/methods/fuzzy-extractor-selfie's TemplateBytes
  });

  it('is deterministic: identical pixels produce identical templates', () => {
    const img1 = pseudoPhoto(200, 200, 42);
    const img2 = pseudoPhoto(200, 200, 42);
    const t1 = deriveTemplateFromPixels(img1);
    const t2 = deriveTemplateFromPixels(img2);
    expect(Array.from(t1)).toEqual(Array.from(t2));
  });

  it('throws on a zero-dimension image', () => {
    expect(() => deriveTemplateFromPixels({ width: 0, height: 10, data: new Uint8ClampedArray(0) })).toThrow();
    expect(() => deriveTemplateFromPixels({ width: 10, height: 0, data: new Uint8ClampedArray(0) })).toThrow();
  });

  it('tolerates small pixel-level noise (a handful of flipped pixels barely moves the template)', () => {
    const base = pseudoPhoto(256, 256, 7);
    const noisy = flipPixels(base, 20); // 20 of 65536 pixels perturbed
    const t1 = deriveTemplateFromPixels(base);
    const t2 = deriveTemplateFromPixels(noisy);
    const dist = hammingDistance(t1, t2);
    // 256 total bits; a handful of perturbed pixels spread across a 16x16
    // downsample grid should move the template by only a small fraction of
    // its bits — nowhere near the ~50% an unrelated image produces (see the
    // "differs substantially" test below). This is what lets the server's
    // fuzzy-extractor Rep() step recover the same commitment from two
    // genuine-but-noisy captures of the same source image.
    expect(dist).toBeLessThan(32); // well under 50% of 256 bits
  });

  it('differs substantially between two unrelated images', () => {
    const imgA = pseudoPhoto(256, 256, 1);
    const imgB = pseudoPhoto(256, 256, 999983);
    const tA = deriveTemplateFromPixels(imgA);
    const tB = deriveTemplateFromPixels(imgB);
    const dist = hammingDistance(tA, tB);
    // Not a strict cryptographic guarantee (this is a perceptual hash, not a
    // hash function), but two unrelated pseudo-random images should land
    // well above the noisy-duplicate threshold exercised above.
    expect(dist).toBeGreaterThan(32);
  });

  it('is invariant to overall brightness shift (thresholds against the image mean, not a fixed constant)', () => {
    const dim = pseudoPhotoScaled(128, 128, 3, 0.5);
    const bright = pseudoPhotoScaled(128, 128, 3, 1.5);
    const tDim = deriveTemplateFromPixels(dim);
    const tBright = deriveTemplateFromPixels(bright);
    // Scaling every pixel by a constant factor preserves each cell's
    // position relative to the grid mean, so mean-thresholding should
    // reproduce (very nearly) the same bit pattern regardless of overall
    // exposure.
    expect(hammingDistance(tDim, tBright)).toBeLessThanOrEqual(16);
  });

  it('ignores the alpha channel', () => {
    const opaque = solidImage(32, 32, [10, 200, 50, 255]);
    const translucent = solidImage(32, 32, [10, 200, 50, 128]);
    expect(Array.from(deriveTemplateFromPixels(opaque))).toEqual(
      Array.from(deriveTemplateFromPixels(translucent)),
    );
  });
});

function pseudoPhotoScaled(width: number, height: number, seed: number, scale: number): PixelBuffer {
  const base = pseudoPhoto(width, height, seed);
  const data = new Uint8ClampedArray(base.data as Uint8ClampedArray);
  for (let i = 0; i < width * height; i++) {
    const idx = i * 4;
    data[idx] = clamp255(data[idx] * scale);
    data[idx + 1] = clamp255(data[idx + 1] * scale);
    data[idx + 2] = clamp255(data[idx + 2] * scale);
  }
  return { width, height, data };
}

function clamp255(v: number): number {
  return Math.max(0, Math.min(255, Math.round(v)));
}

describe('bytesToBase64', () => {
  it('matches the standard base64 alphabet for known bytes', () => {
    // "fuzz" -> ASCII bytes -> known base64.
    const bytes = new Uint8Array([0x66, 0x75, 0x7a, 0x7a]);
    expect(bytesToBase64(bytes)).toBe('ZnV6eg==');
  });

  it('round-trips through atob', () => {
    const bytes = new Uint8Array(TEMPLATE_BYTES);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 37) % 256;
    const b64 = bytesToBase64(bytes);
    const decoded = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });
});
