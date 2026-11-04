// Browser side of the selfie anchor: loads the two on-device models and
// turns camera frames into landmarks and face descriptors.
//
//  - MediaPipe Face Landmarker (Apache-2.0): 478 landmarks + blink
//    blendshapes per frame, for liveness and alignment.
//  - dlib's face-recognition ResNet (public domain weights) via
//    @vladmandic/face-api (MIT) on TensorFlow.js: a 128-number descriptor
//    from an aligned 150x150 face chip.
//
// Both are served from this app's own origin (public/face-models, filled by
// scripts/fetch-face-models.mjs); nothing is fetched from a CDN. Frames
// and descriptors never leave the page. Both libraries are imported lazily
// so the rest of the app does not pay for them.

import type { FaceLandmarker, FaceLandmarkerResult } from '@mediapipe/tasks-vision';
import { CANONICAL_5, CHIP_SIZE, fitSimilarity, fivePointsFromMediapipe } from './align';

const MODEL_BASE = '/face-models';

export type FaceEngine = {
  /** Landmarks + blendshapes for one video frame (timestamps must increase). */
  detect(video: HTMLVideoElement, t: number): FaceLandmarkerResult;
  /** 128-number descriptor of the first face in result, from the same frame. */
  describe(video: HTMLVideoElement, result: FaceLandmarkerResult): Promise<Float32Array>;
};

let loading: Promise<FaceEngine> | null = null;

/** Loads (once) and returns the face engine. */
export function loadFaceEngine(): Promise<FaceEngine> {
  if (!loading) {
    loading = buildEngine().catch((e) => {
      loading = null;
      throw e;
    });
  }
  return loading;
}

async function buildEngine(): Promise<FaceEngine> {
  const [{ FilesetResolver, FaceLandmarker }, faceapi] = await Promise.all([
    import('@mediapipe/tasks-vision'),
    import('@vladmandic/face-api'),
  ]);
  const fileset = await FilesetResolver.forVisionTasks(`${MODEL_BASE}/wasm`);
  const options = (delegate: 'GPU' | 'CPU') => ({
    baseOptions: { modelAssetPath: `${MODEL_BASE}/face_landmarker.task`, delegate },
    runningMode: 'VIDEO' as const,
    // Two, so a second face in view is seen and refused.
    numFaces: 2,
    outputFaceBlendshapes: true,
  });
  let landmarker: FaceLandmarker;
  try {
    landmarker = await FaceLandmarker.createFromOptions(fileset, options('GPU'));
  } catch {
    landmarker = await FaceLandmarker.createFromOptions(fileset, options('CPU'));
  }

  // tf.ready() exists at runtime but is missing from face-api's bundled types.
  await (faceapi.tf as unknown as { ready?: () => Promise<void> }).ready?.();
  await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_BASE);

  const chip = document.createElement('canvas');
  chip.width = chip.height = CHIP_SIZE;
  const ctx = chip.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new Error('2d canvas unavailable');

  return {
    detect: (video, t) => landmarker.detectForVideo(video, t),
    async describe(video, result) {
      const lm = result.faceLandmarks[0];
      if (!lm) throw new Error('no face in this frame');
      const t = fitSimilarity(fivePointsFromMediapipe(lm, video.videoWidth, video.videoHeight), CANONICAL_5);
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, CHIP_SIZE, CHIP_SIZE);
      ctx.setTransform(t.a, t.b, -t.b, t.a, t.tx, t.ty);
      ctx.drawImage(video, 0, 0);
      const d = await faceapi.computeFaceDescriptor(chip);
      return Array.isArray(d) ? d[0] : d;
    },
  };
}

/** Euclidean distance between two descriptors. */
export function descriptorDistance(a: ArrayLike<number>, b: ArrayLike<number>): number {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += (a[i] - b[i]) ** 2;
  return Math.sqrt(s);
}
