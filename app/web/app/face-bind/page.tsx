'use client';

// The document face bind page (see lib/face/facebind.ts). Opened by the
// OpenLine wallet in a WebView: it receives the document photo, runs a short
// liveness check with the camera, and posts back match / liveness / a
// 32-byte template. Nothing is uploaded; there is no network call here
// beyond loading this app's own face models.

import { useEffect, useRef, useState } from 'react';
import { Card } from '@/components/Card';
import { descriptorDistance, loadFaceEngine, type FaceEngine } from '@/lib/face/engine';
import { FAIL_MESSAGES, LivenessCeremony, PROMPTS, frameSignal, type Phase as CeremonyPhase } from '@/lib/face/liveness';
import { TEMPLATE_VERSION, averageDescriptors, binarizeDescriptor, bytesToBase64 } from '@/lib/face/binarize';
import { bindResult, parsePhotoMessage, pickChallenges, type FaceBindError, type FaceBindResult } from '@/lib/face/facebind';

const SAME_FACE_MAX = 0.45;
const DESCRIPTOR_INTERVAL_MS = 250;

type Bridge = { postMessage(msg: string): void };

function post(msg: FaceBindResult | FaceBindError | { type: 'face-bind-ready' }) {
  const rn = (window as unknown as { ReactNativeWebView?: Bridge }).ReactNativeWebView;
  const text = JSON.stringify(msg);
  if (rn) rn.postMessage(text);
  else if (window.parent !== window) window.parent.postMessage(text, '*');
}

function promptFor(p: CeremonyPhase): string {
  switch (p.kind) {
    case 'frontal':
      return p.which === 'start' ? 'Look straight at the camera' : 'Look straight at the camera again';
    case 'challenge':
      return PROMPTS[p.challenge];
    case 'done':
      return 'Done';
    case 'failed':
      return FAIL_MESSAGES[p.reason];
  }
}

async function loadImage(b64: string): Promise<HTMLCanvasElement> {
  const img = new Image();
  img.src = `data:image/jpeg;base64,${b64}`;
  await img.decode();
  // Small document photos are upscaled so the landmarker finds the face.
  const scale = Math.max(1, 480 / Math.max(img.naturalWidth, img.naturalHeight));
  const c = document.createElement('canvas');
  c.width = Math.round(img.naturalWidth * scale);
  c.height = Math.round(img.naturalHeight * scale);
  c.getContext('2d')?.drawImage(img, 0, 0, c.width, c.height);
  return c;
}

export default function FaceBindPage() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const startedRef = useRef(false);
  const [status, setStatus] = useState('Loading the face model…');
  const [prompt, setPrompt] = useState('');
  const [running, setRunning] = useState(false);

  useEffect(() => {
    let engine: FaceEngine | null = null;
    const stop = () => {
      streamRef.current?.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    };
    const fail = (reason: string, text: string) => {
      stop();
      setRunning(false);
      setStatus(text);
      post({ type: 'face-bind-error', reason });
    };

    async function run(photoB64: string) {
      if (startedRef.current || !engine) return;
      startedRef.current = true;
      setStatus('Reading the document photo…');
      let docDesc: Float32Array;
      try {
        const canvas = await loadImage(photoB64);
        const res = engine.detect(canvas, performance.now());
        if (res.faceLandmarks.length !== 1) {
          fail('no_face_in_document', 'No single face was found in the document photo.');
          return;
        }
        docDesc = await engine.describe(canvas, res);
      } catch {
        fail('document_photo_unreadable', 'The document photo could not be read.');
        return;
      }

      let stream: MediaStream;
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } },
          audio: false,
        });
      } catch {
        fail('camera_denied', 'Camera permission was denied.');
        return;
      }
      streamRef.current = stream;
      setRunning(true);
      setStatus('');
      await new Promise((r) => requestAnimationFrame(r));
      const video = videoRef.current;
      if (!video) {
        fail('camera_failed', 'The camera preview did not start.');
        return;
      }
      video.srcObject = stream;
      await video.play();

      const ceremony = new LivenessCeremony(pickChallenges());
      const startDescs: Float32Array[] = [];
      const endDescs: Float32Array[] = [];
      let busy = false;
      let lastDesc = 0;
      let lastT = 0;
      let lastPrompt = '';
      const eng = engine;

      const finish = () => {
        stop();
        setRunning(false);
        const live = averageDescriptors([...startDescs, ...endDescs]);
        const sameFace =
          endDescs.length > 0 && descriptorDistance(averageDescriptors(startDescs), averageDescriptors(endDescs)) <= SAME_FACE_MAX;
        const result = bindResult(
          descriptorDistance(live, docDesc),
          sameFace,
          bytesToBase64(binarizeDescriptor(live)),
          TEMPLATE_VERSION,
        );
        setStatus(result.match && result.liveness ? 'Your face matches the document.' : 'Your face did not match the document photo.');
        post(result);
      };

      const tick = () => {
        if (!streamRef.current) return;
        const t = performance.now();
        if (video.readyState >= 2 && t > lastT) {
          lastT = t;
          const result = eng.detect(video, t);
          const s = frameSignal(t, result.faceLandmarks, result.faceBlendshapes?.map((c) => c.categories), video.videoWidth, video.videoHeight);
          const p = ceremony.onFrame(s);
          const text = promptFor(p);
          if (text !== lastPrompt) {
            lastPrompt = text;
            setPrompt(text);
          }
          if (p.kind === 'failed') {
            fail(`liveness_${p.reason}`, FAIL_MESSAGES[p.reason]);
            return;
          }
          if (p.kind === 'frontal' && !busy && t - lastDesc > DESCRIPTOR_INTERVAL_MS && ceremony.wantsFrontalFrame(s)) {
            busy = true;
            const bucket = p.which === 'start' ? startDescs : endDescs;
            eng
              .describe(video, result)
              .then((d) => {
                bucket.push(d);
                lastDesc = t;
                ceremony.addFrontalFrame(t);
                busy = false;
                if (ceremony.phase.kind === 'done') finish();
              })
              .catch(() => fail('face_model_failed', 'The face model failed.'));
          }
        }
        if (ceremony.phase.kind !== 'done') requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }

    const onMessage = (e: Event) => {
      const photo = parsePhotoMessage((e as MessageEvent).data);
      if (photo) void run(photo);
    };
    window.addEventListener('message', onMessage);
    // react-native-webview delivers to document on Android.
    document.addEventListener('message', onMessage);

    loadFaceEngine()
      .then((e) => {
        engine = e;
        setStatus('Waiting for the document photo…');
        post({ type: 'face-bind-ready' });
      })
      .catch(() => fail('face_model_failed', 'The face model could not be loaded.'));

    return () => {
      window.removeEventListener('message', onMessage);
      document.removeEventListener('message', onMessage);
      stop();
    };
  }, []);

  return (
    <main style={{ maxWidth: 480, margin: '0 auto', padding: 16 }}>
      <Card title="Match your face to your document" status={running ? 'pending' : 'idle'} statusLabel={running ? 'watching' : ''}>
        <p>
          Your document photo and the camera stay on this phone. Only &ldquo;match&rdquo; or &ldquo;no match&rdquo; is
          sent.
        </p>
        {running && (
          <>
            <p style={{ fontSize: 20, fontWeight: 600 }}>{prompt}</p>
            <video ref={videoRef} playsInline muted style={{ width: '100%', transform: 'scaleX(-1)', borderRadius: 8 }} />
          </>
        )}
        {status && <p>{status}</p>}
      </Card>
    </main>
  );
}
