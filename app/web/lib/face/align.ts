// Face alignment math for the selfie anchor (pure, no DOM).
//
// The face-recognition network (dlib's ResNet, via @vladmandic/face-api)
// was trained on 150x150 "face chips" in which the eyes, nose and mouth sit
// at roughly fixed positions. We find five points on the live face with
// MediaPipe Face Landmarker, fit the similarity transform (rotation +
// uniform scale + shift) that moves them onto CANONICAL_5, and draw the
// frame through that transform into a 150x150 canvas.

export type Pt = { x: number; y: number };

/** Side of the square chip the recognition network expects. */
export const CHIP_SIZE = 150;

/**
 * Where the five points land in the chip, in this order: the eye on the
 * left of the image, the eye on the right of the image, the nose tip, the
 * mouth corner on the left of the image, the mouth corner on the right.
 * The layout was picked by measurement (docs/selfie-anchor.md): a dlib-like
 * layout scaled up 1.7x about the chip centre, i.e. a tight crop of eyes,
 * nose and mouth, separated unrelated faces best. Part of the template
 * version (see binarize.ts): changing it changes every template.
 */
export const CANONICAL_5: readonly Pt[] = [
  { x: 41, y: 56.3 },
  { x: 109, y: 56.3 },
  { x: 75, y: 93.7 },
  { x: 47.8, y: 127.7 },
  { x: 102.2, y: 127.7 },
];

/**
 * MediaPipe Face Landmarker (478-point mesh with irises) indices for the
 * five points, in CANONICAL_5 order. With a front camera the subject's
 * right eye is on the left of the image.
 *  468 / 473: iris centres; 1: nose tip; 61 / 291: mouth corners.
 */
export const MEDIAPIPE_5 = [468, 473, 1, 61, 291] as const;

/** A 2D similarity transform: x' = a*x - b*y + tx, y' = b*x + a*y + ty. */
export type Similarity = { a: number; b: number; tx: number; ty: number };

/**
 * Least-squares similarity transform taking src onto dst (Umeyama 1991,
 * restricted to 2D). src and dst must have the same length (>= 2).
 */
export function fitSimilarity(src: readonly Pt[], dst: readonly Pt[]): Similarity {
  const n = src.length;
  if (n < 2 || dst.length !== n) throw new Error('fitSimilarity: need >= 2 matching points');
  let sx = 0, sy = 0, dx = 0, dy = 0;
  for (let i = 0; i < n; i++) {
    sx += src[i].x; sy += src[i].y; dx += dst[i].x; dy += dst[i].y;
  }
  sx /= n; sy /= n; dx /= n; dy /= n;
  let num1 = 0, num2 = 0, den = 0;
  for (let i = 0; i < n; i++) {
    const px = src[i].x - sx, py = src[i].y - sy;
    const qx = dst[i].x - dx, qy = dst[i].y - dy;
    num1 += px * qx + py * qy;
    num2 += px * qy - py * qx;
    den += px * px + py * py;
  }
  if (den === 0) throw new Error('fitSimilarity: degenerate source points');
  const a = num1 / den;
  const b = num2 / den;
  return { a, b, tx: dx - (a * sx - b * sy), ty: dy - (b * sx + a * sy) };
}

/** Applies t to p. */
export function applySimilarity(t: Similarity, p: Pt): Pt {
  return { x: t.a * p.x - t.b * p.y + t.tx, y: t.b * p.x + t.a * p.y + t.ty };
}

/**
 * Picks the five alignment points out of a MediaPipe landmark list
 * (normalized 0..1 coordinates) and scales them to pixels.
 */
export function fivePointsFromMediapipe(
  landmarks: readonly { x: number; y: number }[],
  width: number,
  height: number,
): Pt[] {
  return MEDIAPIPE_5.map((i) => {
    const l = landmarks[i];
    if (!l) throw new Error(`landmark ${i} missing (need the 478-point model)`);
    return { x: l.x * width, y: l.y * height };
  });
}
