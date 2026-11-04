import { describe, expect, it } from 'vitest';
import { CANONICAL_5, applySimilarity, fitSimilarity, fivePointsFromMediapipe, MEDIAPIPE_5 } from './align';
import {
  DESCRIPTOR_DIM,
  POPULATION_MEAN_V1,
  TEMPLATE_BYTES,
  TEMPLATE_VERSION,
  averageDescriptors,
  binarizeDescriptor,
  bytesToBase64,
  hammingDistance,
} from './binarize';
import {
  CHALLENGE_TIMEOUT_MS,
  FRONTAL_FRAMES_EACH,
  LivenessCeremony,
  PARALLAX_POINTS,
  YAW_TURNED,
  frameSignal,
  parallaxScore,
  type ChallengeKind,
  type FrameSignal,
} from './liveness';

// Deterministic pseudo-random numbers for fixtures.
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function randomDescriptor(seed: number): number[] {
  const r = rng(seed);
  return POPULATION_MEAN_V1.map((m) => m + (r() - 0.5) * 0.3);
}

describe('align', () => {
  it('fits an exact similarity transform', () => {
    const t = { a: 0.8, b: 0.3, tx: 12, ty: -7 };
    const src = [{ x: 10, y: 20 }, { x: 50, y: 22 }, { x: 30, y: 45 }, { x: 15, y: 70 }, { x: 45, y: 71 }];
    const dst = src.map((p) => applySimilarity(t, p));
    const got = fitSimilarity(src, dst);
    expect(got.a).toBeCloseTo(t.a, 9);
    expect(got.b).toBeCloseTo(t.b, 9);
    expect(got.tx).toBeCloseTo(t.tx, 9);
    expect(got.ty).toBeCloseTo(t.ty, 9);
  });

  it('maps a face onto the canonical chip layout', () => {
    const face = [{ x: 200, y: 210 }, { x: 280, y: 205 }, { x: 240, y: 260 }, { x: 210, y: 300 }, { x: 270, y: 296 }];
    const t = fitSimilarity(face, CANONICAL_5);
    const mapped = face.map((p) => applySimilarity(t, p));
    mapped.forEach((p, i) => {
      expect(Math.abs(p.x - CANONICAL_5[i].x)).toBeLessThan(6);
      expect(Math.abs(p.y - CANONICAL_5[i].y)).toBeLessThan(6);
    });
  });

  it('rejects degenerate input', () => {
    expect(() => fitSimilarity([{ x: 1, y: 1 }], [{ x: 1, y: 1 }])).toThrow();
    expect(() => fitSimilarity([{ x: 1, y: 1 }, { x: 1, y: 1 }], [{ x: 0, y: 0 }, { x: 2, y: 2 }])).toThrow();
  });

  it('reads the five MediaPipe points in pixels', () => {
    const lm = Array.from({ length: 478 }, (_, i) => ({ x: i / 1000, y: i / 2000 }));
    const pts = fivePointsFromMediapipe(lm, 1000, 2000);
    expect(pts.map((p) => p.x)).toEqual(MEDIAPIPE_5.map((i) => i));
    expect(() => fivePointsFromMediapipe(lm.slice(0, 468), 10, 10)).toThrow(/478/);
  });
});

describe('binarize', () => {
  it('matches the issuer contract', () => {
    expect(TEMPLATE_BYTES).toBe(32); // src/methods/fuzzy-extractor-selfie TemplateBytes
    expect(TEMPLATE_VERSION).toBe('dlib128-simhash256-v1'); // DefaultTemplateVersion
    expect(POPULATION_MEAN_V1).toHaveLength(DESCRIPTOR_DIM);
  });

  it('is deterministic and pinned', () => {
    const d = randomDescriptor(7);
    const a = binarizeDescriptor(d);
    expect(a).toHaveLength(32);
    expect(binarizeDescriptor(d)).toEqual(a);
    // Pins the projection matrix: if this changes, every enrolled template
    // changes too (bump TEMPLATE_VERSION instead).
    expect(bytesToBase64(binarizeDescriptor(Array.from({ length: 128 }, (_, i) => POPULATION_MEAN_V1[i] + (i % 3) - 1)))).toMatchInlineSnapshot(`"nGv0IZcoVazh/bWIYkt16zDMOWFoERbT5kjIWbVOyaE="`);
  });

  it('keeps near descriptors near and far ones far', () => {
    const base = randomDescriptor(1);
    const r = rng(99);
    const near = base.map((v) => v + (r() - 0.5) * 0.02);
    expect(hammingDistance(binarizeDescriptor(base), binarizeDescriptor(near))).toBeLessThan(40);
    let far = 0;
    for (let s = 2; s < 12; s++) far += hammingDistance(binarizeDescriptor(base), binarizeDescriptor(randomDescriptor(s)));
    expect(far / 10).toBeGreaterThan(90); // about half of 256 bits
  });

  it('centres on the population mean (the mean itself hashes to all zeros)', () => {
    expect(Array.from(binarizeDescriptor(POPULATION_MEAN_V1))).toEqual(new Array(32).fill(0));
  });

  it('averages descriptors and rejects wrong lengths', () => {
    const avg = averageDescriptors([[...new Array(128).fill(1)], [...new Array(128).fill(3)]]);
    expect(avg[0]).toBe(2);
    expect(() => averageDescriptors([])).toThrow();
    expect(() => binarizeDescriptor([1, 2, 3])).toThrow(/128/);
  });
});

// A synthetic face for the ceremony: frame signals with the given pose.
function frame(t: number, opts: Partial<FrameSignal> & { turn?: number } = {}): FrameSignal {
  const turn = opts.turn ?? 0;
  // Frontal geometry with the nose (last point) pushed sideways by 3D turn.
  const pts = PARALLAX_POINTS.map((_, i) => ({ x: 100 + i * 10, y: 100 + (i % 4) * 15 }));
  pts[pts.length - 1] = { x: 150 + turn * 120, y: 140 };
  return { t, faces: 1, yaw: turn, blink: 0.05, size: 0.3, pts, ...opts };
}

/** Plays a ceremony to the end with a scripted performer; returns the ceremony. */
function perform(challenges: ChallengeKind[], opts: { reactMs?: number; flat?: boolean } = {}) {
  const c = new LivenessCeremony(challenges);
  let t = 1000;
  const step = 33;
  const push = (f: FrameSignal) => c.onFrame(f);
  const frontal = () => {
    for (let i = 0; i < FRONTAL_FRAMES_EACH; i++) {
      t += 300;
      const f = frame(t);
      push(f);
      expect(c.wantsFrontalFrame(f)).toBe(true);
      c.addFrontalFrame(t);
    }
  };
  frontal();
  for (const ch of challenges) {
    if (c.phase.kind !== 'challenge') break;
    const react = opts.reactMs ?? 600;
    for (let w = 0; w < react; w += step) push(frame((t += step)));
    if (ch === 'turn_left' || ch === 'turn_right') {
      const dir = ch === 'turn_left' ? 1 : -1;
      const yaw = dir * (YAW_TURNED + 0.05);
      const f = frame((t += step), { turn: yaw });
      if (opts.flat) f.pts = frame(t).pts; // a flat photo: nose follows the outline
      push(f);
    } else if (ch === 'blink') {
      push(frame((t += step), { blink: 0.9 }));
      push(frame((t += 120), { blink: 0.9 }));
      push(frame((t += step), { blink: 0.05 }));
    } else {
      push(frame((t += step), { size: 0.45 }));
    }
    // back to neutral
    push(frame((t += step)));
  }
  if (c.phase.kind === 'frontal') frontal();
  return c;
}

describe('liveness ceremony', () => {
  it('passes a live performer through every challenge order', () => {
    const kinds: ChallengeKind[] = ['turn_left', 'turn_right', 'blink', 'closer'];
    for (const a of kinds) for (const b of kinds) for (const d of kinds) {
      if (new Set([a, b, d]).size < 3) continue;
      const c = perform([a, b, d]);
      expect(c.phase.kind, `${a},${b},${d}`).toBe('done');
      expect(c.results.map((r) => r.kind)).toEqual([a, b, d]);
      c.results.forEach((r) => expect(r.ms).toBeGreaterThanOrEqual(250));
    }
  });

  it('reports evidence the issuer can check', () => {
    const c = perform(['blink', 'turn_left', 'closer']);
    const ev = c.evidence(6);
    expect(ev.frames).toBe(6);
    expect(ev.challenges).toHaveLength(3);
    expect(ev.parallax.length).toBe(1);
    expect(ev.parallax[0]).toBeGreaterThan(0.05);
  });

  it('refuses the wrong turn direction (times out)', () => {
    const c = new LivenessCeremony(['turn_left', 'blink', 'closer']);
    let t = 0;
    for (let i = 0; i < FRONTAL_FRAMES_EACH; i++) {
      c.onFrame(frame((t += 300)));
      c.addFrontalFrame(t);
    }
    c.onFrame(frame((t += 300)));
    for (let i = 0; i < 400 && c.phase.kind === 'challenge'; i++) c.onFrame(frame((t += 33), { turn: -0.3 }));
    expect(c.phase).toEqual({ kind: 'failed', reason: 'timeout' });
    expect(t).toBeGreaterThan(CHALLENGE_TIMEOUT_MS);
  });

  it('refuses an answer faster than a person can react', () => {
    const c = perform(['closer', 'blink', 'turn_right'], { reactMs: 100 });
    expect(c.phase).toEqual({ kind: 'failed', reason: 'too_fast' });
  });

  it('refuses a flat face (no motion parallax on the turn)', () => {
    const c = perform(['turn_left', 'blink', 'closer'], { flat: true });
    expect(c.phase).toEqual({ kind: 'failed', reason: 'flat_face' });
  });

  it('refuses a second face', () => {
    const c = new LivenessCeremony(['blink', 'closer', 'turn_left']);
    c.onFrame(frame(0));
    expect(c.onFrame(frame(33, { faces: 2 }))).toEqual({ kind: 'failed', reason: 'multiple_faces' });
  });

  it('refuses a face that leaves the frame', () => {
    const c = new LivenessCeremony(['blink', 'closer', 'turn_left']);
    c.onFrame(frame(0));
    c.onFrame({ ...frame(500), faces: 0 });
    expect(c.onFrame({ ...frame(2000), faces: 0 })).toEqual({ kind: 'failed', reason: 'no_face' });
  });

  it('runs frontal-only for a legacy issuer with no challenges', () => {
    const c = perform([]);
    expect(c.phase.kind).toBe('done');
  });

  it('rejects unknown challenge kinds', () => {
    expect(() => new LivenessCeremony(['smile' as ChallengeKind])).toThrow();
  });
});

describe('parallax', () => {
  it('is ~0 for an affine (flat) motion and large for a nose moving against the outline', () => {
    const f = PARALLAX_POINTS.map((_, i) => ({ x: 100 + i * 9, y: 80 + (i % 5) * 13 }));
    f[f.length - 1] = { x: 150, y: 120 };
    const affine = f.map((p) => ({ x: 0.85 * p.x + 0.05 * p.y + 10, y: 0.02 * p.x + p.y - 3 }));
    expect(parallaxScore(f, affine)).toBeLessThan(1e-6);
    const real = affine.map((p) => ({ ...p }));
    real[real.length - 1] = { x: real[real.length - 1].x + 12, y: real[real.length - 1].y };
    expect(parallaxScore(f, real)).toBeGreaterThan(0.1);
  });
});

describe('frameSignal', () => {
  it('reads yaw, blink and size from landmarks', () => {
    const lm = Array.from({ length: 478 }, () => ({ x: 0.5, y: 0.5 }));
    lm[234] = { x: 0.3, y: 0.5 };
    lm[454] = { x: 0.7, y: 0.5 };
    lm[1] = { x: 0.6, y: 0.5 }; // nose toward image right = person's left
    const s = frameSignal(5, [lm], [[{ categoryName: 'eyeBlinkLeft', score: 0.8 }, { categoryName: 'eyeBlinkRight', score: 0.6 }]], 640, 480);
    expect(s.yaw).toBeCloseTo(0.25);
    expect(s.blink).toBeCloseTo(0.6);
    expect(s.size).toBeCloseTo(0.4);
    expect(s.pts).toHaveLength(PARALLAX_POINTS.length);
    expect(frameSignal(5, [], undefined, 640, 480).faces).toBe(0);
  });
});
