// DOM-touching capture helpers for the fuzzy-extractor-selfie step
// (components/steps/SelfieStep.tsx). Kept separate from lib/selfieTemplate.ts
// so the pure feature-derivation math stays unit-testable without a
// browser/canvas environment.
//
// Two capture paths, both funneling into the same
// deriveTemplateFromPixels(PixelBuffer):
//   1. Live camera (getUserMedia + <video> + <canvas> frame grab) — the real
//      end-user path.
//   2. An uploaded image file — the fallback SelfieStep always offers, both
//      for browsers/environments without camera access (or where the user
//      declines the permission prompt) and so this step can be driven
//      end-to-end by an automated (headless-browser) test with a fixture
//      image, without needing a fake camera device.

import { deriveTemplateFromPixels, type PixelBuffer } from './selfieTemplate';

export function isCameraAvailable(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    typeof navigator.mediaDevices !== 'undefined' &&
    typeof navigator.mediaDevices.getUserMedia === 'function'
  );
}

/** Requests the front-facing camera. Throws (e.g. NotAllowedError) if denied. */
export async function openCameraStream(): Promise<MediaStream> {
  if (!isCameraAvailable()) {
    throw new Error('camera not available in this browser');
  }
  return navigator.mediaDevices.getUserMedia({
    video: { facingMode: 'user' },
    audio: false,
  });
}

export function stopCameraStream(stream: MediaStream | null): void {
  stream?.getTracks().forEach((t) => t.stop());
}

/** Draws the current frame of a playing <video> element into a PixelBuffer. */
export function captureFrameFromVideo(video: HTMLVideoElement): PixelBuffer {
  const width = video.videoWidth;
  const height = video.videoHeight;
  if (!width || !height) {
    throw new Error('video has no frame ready yet');
  }
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('2d canvas context unavailable');
  ctx.drawImage(video, 0, 0, width, height);
  const imageData = ctx.getImageData(0, 0, width, height);
  return { width: imageData.width, height: imageData.height, data: imageData.data };
}

/** Decodes an uploaded image File (or Blob) into a PixelBuffer via canvas. */
export async function pixelBufferFromFile(file: File | Blob): Promise<PixelBuffer> {
  const bitmap = await createImageBitmap(file);
  try {
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('2d canvas context unavailable');
    ctx.drawImage(bitmap, 0, 0);
    const imageData = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
    return { width: imageData.width, height: imageData.height, data: imageData.data };
  } finally {
    bitmap.close();
  }
}

/** Convenience: capture a video frame and derive its template in one call. */
export function deriveTemplateFromVideoFrame(video: HTMLVideoElement) {
  return deriveTemplateFromPixels(captureFrameFromVideo(video));
}

/** Convenience: decode an uploaded file and derive its template in one call. */
export async function deriveTemplateFromFile(file: File | Blob) {
  return deriveTemplateFromPixels(await pixelBufferFromFile(file));
}
