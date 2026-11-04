// Active liveness for the selfie anchor (pure logic, no DOM).
//
// The issuer picks three of four challenges in a random order (turn left,
// turn right, blink, move closer). The person does them in front of the
// camera while MediaPipe Face Landmarker tracks the face; this module turns
// each frame's landmarks into a few numbers and runs the ceremony as a
// state machine:
//
//   look straight (collect frontal frames for the face template)
//   -> challenge 1 -> challenge 2 -> challenge 3
//   -> look straight again (collect more frontal frames)
//
// Each challenge must start from a neutral pose after its prompt appears,
// be seen within CHALLENGE_TIMEOUT_MS, and take at least MIN_REACTION_MS
// (faster than a person can react to a prompt they just saw). Exactly one
// face must be in view throughout. Head turns are also scored for motion
// parallax (see parallaxScore): a real head is 3D, so the nose moves
// against the face outline in a way a flat photo or screen turned in front
// of the camera cannot.
//
// What this cannot do: tell a real camera from a virtual one fed by a
// real-time face-swap. docs/selfie-anchor.md has the threat model.

import type { Pt } from './align';

export type ChallengeKind = 'turn_left' | 'turn_right' | 'blink' | 'closer';
export const CHALLENGE_KINDS: readonly ChallengeKind[] = ['turn_left', 'turn_right', 'blink', 'closer'];

export const PROMPTS: Record<ChallengeKind, string> = {
  turn_left: 'Turn your head to your left',
  turn_right: 'Turn your head to your right',
  blink: 'Blink',
  closer: 'Move the phone closer to your face',
};

/** Mirrors the issuer's MinChallengeMS. */
export const MIN_REACTION_MS = 250;
export const CHALLENGE_TIMEOUT_MS = 8000;
/** Frontal frames collected before and after the challenges. */
export const FRONTAL_FRAMES_EACH = 3;
export const FRONTAL_TIMEOUT_MS = 10000;
/** A face missing for longer than this ends the ceremony. */
export const FACE_LOST_MS = 1200;

// Pose thresholds. yaw is the nose's offset from the middle of the face
// outline, as a fraction of face width: 0 frontal, about +-0.25 at 30 deg.
export const YAW_NEUTRAL = 0.07;
export const YAW_TURNED = 0.16;
export const BLINK_CLOSED = 0.5;
export const BLINK_OPEN = 0.3;
export const BLINK_MAX_CLOSED_MS = 1500;
export const CLOSER_RATIO = 1.25;
/** Minimum face width (fraction of frame width) to use a frame. */
export const MIN_FACE_SIZE = 0.18;
/**
 * Minimum best parallax score over the ceremony's head turns. Measured on
 * the London Set (docs/selfie-anchor.md): real 3/4 turns score 0.27-0.44
 * (about 0.58 x yaw, so ~0.09 at the YAW_TURNED threshold); frontal photos
 * warped as if a flat print were turned 25-40 deg score 0.001-0.063 and,
 * more to the point, never reach YAW_TURNED at all (max yaw 0.09), because
 * a flat picture's nose stays centred between its face edges.
 */
export const PARALLAX_MIN = 0.05;

/** One frame, reduced to what the ceremony needs. */
export type FrameSignal = {
  /** ms, monotonic. */
  t: number;
  faces: number;
  /** + means the person's own left (image right with an unmirrored front camera). */
  yaw: number;
  /** Both eyes' blink score (min of left and right blendshapes), 0 open .. 1 closed. */
  blink: number;
  /** Face width / frame width. */
  size: number;
  /** Landmarks used for the parallax score, in pixels (PARALLAX_POINTS order). */
  pts: Pt[];
};

// MediaPipe 478-point mesh indices.
const NOSE_TIP = 1;
const FACE_EDGE_IMAGE_LEFT = 234;
const FACE_EDGE_IMAGE_RIGHT = 454;
/**
 * Points for the parallax fit: eye corners, mouth corners, brow-line top,
 * chin, face edges, and (last) the nose tip, which is the one tested.
 */
export const PARALLAX_POINTS = [33, 133, 362, 263, 61, 291, 10, 152, 234, 454, NOSE_TIP] as const;

type Landmark = { x: number; y: number };
type Category = { categoryName: string; score: number };

/** Reduces one Face Landmarker result to a FrameSignal. */
export function frameSignal(
  t: number,
  faces: readonly (readonly Landmark[])[],
  blendshapes: readonly (readonly Category[])[] | undefined,
  width: number,
  height: number,
): FrameSignal {
  if (faces.length === 0) return { t, faces: 0, yaw: 0, blink: 0, size: 0, pts: [] };
  const lm = faces[0];
  const l = lm[FACE_EDGE_IMAGE_LEFT];
  const r = lm[FACE_EDGE_IMAGE_RIGHT];
  const nose = lm[NOSE_TIP];
  const span = r.x - l.x;
  const yaw = span > 0 ? (nose.x - l.x) / span - 0.5 : 0;
  let bl = 0, br = 0;
  for (const c of blendshapes?.[0] ?? []) {
    if (c.categoryName === 'eyeBlinkLeft') bl = c.score;
    if (c.categoryName === 'eyeBlinkRight') br = c.score;
  }
  return {
    t,
    faces: faces.length,
    yaw,
    blink: Math.min(bl, br),
    size: Math.abs(span),
    pts: PARALLAX_POINTS.map((i) => ({ x: lm[i].x * width, y: lm[i].y * height })),
  };
}

/**
 * Motion-parallax score between a frontal frame and a turned frame: fit the
 * best 2D affine map from the frontal points to the turned points (all but
 * the nose tip), then measure how far the nose tip lands from where that map
 * predicts, in units of the frontal inter-ocular distance.
 *
 * A flat picture turned in front of the camera moves (nearly) by one affine
 * map, so the nose follows the prediction. A real head is 3D: the nose sits
 * well in front of the eyes and the face outline, so turning moves it
 * against them and the residual is large.
 */
export function parallaxScore(frontal: readonly Pt[], turned: readonly Pt[]): number {
  const n = PARALLAX_POINTS.length - 1;
  if (frontal.length !== PARALLAX_POINTS.length || turned.length !== PARALLAX_POINTS.length) return 0;
  // Least squares for [x' y'] = [x y 1] * M (M is 3x2) via normal equations.
  const ata = [0, 0, 0, 0, 0, 0, 0, 0, 0];
  const atx = [0, 0, 0];
  const aty = [0, 0, 0];
  for (let i = 0; i < n; i++) {
    const row = [frontal[i].x, frontal[i].y, 1];
    for (let a = 0; a < 3; a++) {
      for (let b = 0; b < 3; b++) ata[a * 3 + b] += row[a] * row[b];
      atx[a] += row[a] * turned[i].x;
      aty[a] += row[a] * turned[i].y;
    }
  }
  const inv = invert3(ata);
  if (!inv) return 0;
  const mx = mul3(inv, atx);
  const my = mul3(inv, aty);
  const nose = frontal[n];
  const px = mx[0] * nose.x + mx[1] * nose.y + mx[2];
  const py = my[0] * nose.x + my[1] * nose.y + my[2];
  const iod = Math.hypot(frontal[3].x - frontal[0].x, frontal[3].y - frontal[0].y);
  if (iod === 0) return 0;
  return Math.hypot(turned[n].x - px, turned[n].y - py) / iod;
}

function invert3(m: number[]): number[] | null {
  const [a, b, c, d, e, f, g, h, i] = m;
  const A = e * i - f * h, B = -(d * i - f * g), C = d * h - e * g;
  const det = a * A + b * B + c * C;
  if (Math.abs(det) < 1e-9) return null;
  return [
    A / det, -(b * i - c * h) / det, (b * f - c * e) / det,
    B / det, (a * i - c * g) / det, -(a * f - c * d) / det,
    C / det, -(a * h - b * g) / det, (a * e - b * d) / det,
  ];
}

function mul3(m: number[], v: number[]): number[] {
  return [0, 1, 2].map((r) => m[r * 3] * v[0] + m[r * 3 + 1] * v[1] + m[r * 3 + 2] * v[2]);
}

export type ChallengeResult = { kind: ChallengeKind; ms: number };

export type Phase =
  | { kind: 'frontal'; which: 'start' | 'end' }
  | { kind: 'challenge'; index: number; challenge: ChallengeKind; promptAt: number }
  | { kind: 'done' }
  | { kind: 'failed'; reason: FailReason };

export type FailReason = 'no_face' | 'multiple_faces' | 'timeout' | 'too_fast' | 'flat_face';

export const FAIL_MESSAGES: Record<FailReason, string> = {
  no_face: 'We lost your face. Keep it in the frame, in good light.',
  multiple_faces: 'More than one face is in view. Only you should be in the frame.',
  timeout: 'That took too long. Try again and follow each prompt as it appears.',
  too_fast: 'That was faster than anyone can react. Wait for each prompt, then do it.',
  flat_face: 'Your head turn did not look like a real 3D face. Try again, turning your head (not the phone).',
};

/**
 * The ceremony state machine. Feed it every frame with onFrame; read phase
 * to drive the UI. wantsFrontalFrame tells the caller when to compute a
 * face descriptor from the current frame (frontal phases only), and the
 * caller reports each one with addFrontalFrame.
 */
export class LivenessCeremony {
  readonly challenges: readonly ChallengeKind[];
  phase: Phase = { kind: 'frontal', which: 'start' };
  readonly results: ChallengeResult[] = [];
  readonly parallax: number[] = [];

  private phaseStart = -1;
  private lastFaceAt = -1;
  private frontalCount = 0;
  private sawNeutral = false;
  private neutralPts: Pt[] | null = null;
  private baselineSize = 0;
  private closedAt = -1;

  constructor(challenges: readonly ChallengeKind[]) {
    // An empty list is the legacy issuer (FUZZY_EXTRACTOR_ENABLED): frontal
    // frames only, no challenges.
    for (const c of challenges) if (!CHALLENGE_KINDS.includes(c)) throw new Error(`unknown challenge ${c}`);
    this.challenges = challenges;
  }

  /** True when the current frame is a good frontal frame to take a descriptor from. */
  wantsFrontalFrame(s: FrameSignal): boolean {
    return this.phase.kind === 'frontal' && isNeutral(s) && s.size >= MIN_FACE_SIZE;
  }

  /** Report that a frontal descriptor was taken from the frame at time t. */
  addFrontalFrame(t: number): void {
    if (this.phase.kind !== 'frontal') return;
    this.frontalCount++;
    if (this.frontalCount < FRONTAL_FRAMES_EACH) return;
    this.frontalCount = 0;
    if (this.phase.which === 'start' && this.challenges.length > 0) this.startChallenge(0, t);
    else this.finish();
  }

  onFrame(s: FrameSignal): Phase {
    if (this.phase.kind === 'done' || this.phase.kind === 'failed') return this.phase;
    if (this.phaseStart < 0) this.phaseStart = s.t;
    if (this.lastFaceAt < 0) this.lastFaceAt = s.t;

    if (s.faces > 1) return this.fail('multiple_faces');
    if (s.faces === 0) {
      if (s.t - this.lastFaceAt > FACE_LOST_MS) return this.fail('no_face');
      return this.phase;
    }
    this.lastFaceAt = s.t;

    if (this.phase.kind === 'frontal') {
      if (s.t - this.phaseStart > FRONTAL_TIMEOUT_MS) return this.fail('timeout');
      return this.phase;
    }

    const p = this.phase;
    const elapsed = s.t - p.promptAt;
    if (elapsed > CHALLENGE_TIMEOUT_MS) return this.fail('timeout');

    // Every challenge starts from a neutral pose seen after its prompt.
    if (!this.sawNeutral) {
      if (isNeutral(s)) {
        this.sawNeutral = true;
        this.neutralPts = s.pts;
        this.baselineSize = s.size;
      }
      return this.phase;
    }
    if (isNeutral(s) && p.challenge !== 'closer') {
      // Keep the latest neutral frame as the parallax reference.
      this.neutralPts = s.pts;
    }

    let done = false;
    switch (p.challenge) {
      case 'turn_left':
      case 'turn_right': {
        const dir = p.challenge === 'turn_left' ? 1 : -1;
        if (s.yaw * dir > YAW_TURNED) {
          done = true;
          if (this.neutralPts) this.parallax.push(round3(parallaxScore(this.neutralPts, s.pts)));
        }
        break;
      }
      case 'blink':
        if (s.blink > BLINK_CLOSED) {
          if (this.closedAt < 0) this.closedAt = s.t;
        } else if (this.closedAt >= 0 && s.blink < BLINK_OPEN) {
          done = s.t - this.closedAt <= BLINK_MAX_CLOSED_MS;
          this.closedAt = -1;
        }
        break;
      case 'closer':
        done = s.size >= this.baselineSize * CLOSER_RATIO && Math.abs(s.yaw) < YAW_TURNED;
        break;
    }
    if (!done) return this.phase;
    if (elapsed < MIN_REACTION_MS) return this.fail('too_fast');
    this.results.push({ kind: p.challenge, ms: Math.round(elapsed) });
    if (p.index + 1 < this.challenges.length) this.startChallenge(p.index + 1, s.t);
    else this.endChallenges(s.t);
    return this.phase;
  }

  /** The evidence object the issuer expects (minus frames, which the caller knows). */
  evidence(frames: number) {
    return { challenges: this.results, frames, parallax: this.parallax };
  }

  private startChallenge(index: number, t: number) {
    this.phase = { kind: 'challenge', index, challenge: this.challenges[index], promptAt: t };
    this.phaseStart = t;
    this.sawNeutral = false;
    this.neutralPts = null;
    this.closedAt = -1;
  }

  private endChallenges(t: number) {
    const turns = this.challenges.filter((c) => c === 'turn_left' || c === 'turn_right').length;
    if (turns > 0 && Math.max(0, ...this.parallax) < PARALLAX_MIN) {
      this.fail('flat_face');
      return;
    }
    this.phase = { kind: 'frontal', which: 'end' };
    this.phaseStart = t;
  }

  private finish() {
    this.phase = { kind: 'done' };
  }

  private fail(reason: FailReason): Phase {
    this.phase = { kind: 'failed', reason };
    return this.phase;
  }
}

function isNeutral(s: FrameSignal): boolean {
  return Math.abs(s.yaw) < YAW_NEUTRAL && s.blink < BLINK_OPEN;
}

function round3(x: number): number {
  return Math.round(x * 1000) / 1000;
}
