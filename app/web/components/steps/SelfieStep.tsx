'use client';

import { useEffect, useRef, useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import type { Status } from '../StatusPill';
import { friendlyError, isSessionExpired } from '@/lib/errors';
import { beginMethod, completeMethod, type StartEnrollmentResponse } from '@/lib/api';
import { descriptorDistance, loadFaceEngine, type FaceEngine } from '@/lib/face/engine';
import {
  FAIL_MESSAGES,
  LivenessCeremony,
  PROMPTS,
  frameSignal,
  type ChallengeKind,
  type Phase as CeremonyPhase,
} from '@/lib/face/liveness';
import { TEMPLATE_VERSION, averageDescriptors, binarizeDescriptor, bytesToBase64 } from '@/lib/face/binarize';

// fuzzy-extractor-selfie's stable plugin id (src/methods/fuzzy-extractor-selfie).
const METHOD_ID = 'fuzzy-extractor-selfie';

/**
 * Largest descriptor distance allowed between the frontal frames taken
 * before and after the challenges. The same face seconds apart measures
 * well under 0.3; different faces averaged 0.77 on the London Set.
 */
const SAME_FACE_MAX = 0.45;
/** Least time between two descriptor computations. */
const DESCRIPTOR_INTERVAL_MS = 250;

type Phase = 'idle' | 'loading' | 'running' | 'submitting' | 'done' | 'error' | 'unavailable';

const SERVER_REASONS: Record<string, string> = {
  duplicate_person_detected:
    'This face already has a Personhood identity, so it cannot enroll again. Each person enrolls once.',
  liveness_too_fast: 'That finished faster than a person can. Please try again.',
  liveness_timing_implausible: 'The timing of the challenges did not look human. Please try again.',
  liveness_challenge_mismatch: 'The challenges came back in the wrong order. Please try again.',
  challenge_expired: 'The challenge expired. Please try again.',
  invalid_challenge_token: 'The challenge expired or the issuer restarted. Please try again.',
  unsupported_template_version: 'This app is out of date with the issuer. Reload the page and try again.',
};

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

export function SelfieStep({
  session,
  onSessionExpired,
  available,
  done,
  onVerified,
  onSkip,
  onContinue,
}: {
  session: StartEnrollmentResponse;
  /** Called when the server reports the session is gone (expired). */
  onSessionExpired?: () => void;
  available: boolean;
  done: boolean;
  onVerified: () => void;
  onSkip: () => void;
  onContinue: () => void;
}) {
  const [phase, setPhase] = useState<Phase>(done ? 'done' : available ? 'idle' : 'unavailable');
  const [statusText, setStatusText] = useState(done ? 'verified' : available ? 'ready' : 'method not registered');
  const [prompt, setPrompt] = useState('');
  const [stepLabel, setStepLabel] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [debugLine, setDebugLine] = useState('');
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number>(0);
  const promptRef = useRef<HTMLParagraphElement | null>(null);
  const debug = typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('selfiedebug');

  const status: Status =
    phase === 'done' ? 'ok' : phase === 'error' ? 'error' : phase === 'idle' || phase === 'unavailable' ? 'idle' : 'pending';

  function stopCamera() {
    cancelAnimationFrame(rafRef.current);
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
  }

  useEffect(() => stopCamera, []);

  function fail(message: string, label = 'failed') {
    stopCamera();
    setPhase('error');
    setStatusText(label);
    setErr(message);
  }

  async function start() {
    setErr(null);
    setPhase('loading');
    setStatusText('loading face model');
    setPrompt('');
    try {
      if (!navigator.mediaDevices?.getUserMedia) throw new Error('This browser has no camera access.');
      const [engine, begin, stream] = await Promise.all([
        loadFaceEngine(),
        beginMethod(METHOD_ID, session.session_id, ''),
        navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } },
          audio: false,
        }),
      ]);
      streamRef.current = stream;
      setPhase('running');
      setStatusText('watching');
      // The <video> only exists once phase is 'running'; wait a frame for it.
      await new Promise((r) => requestAnimationFrame(r));
      const video = videoRef.current;
      if (!video) throw new Error('camera preview did not appear');
      promptRef.current?.scrollIntoView({ block: 'start', behavior: 'smooth' });
      video.srcObject = stream;
      await video.play();

      const payload = begin.challenge.payload ?? {};
      const challenges = (Array.isArray(payload.challenges) ? payload.challenges : []) as ChallengeKind[];
      const token = typeof payload.challenge_token === 'string' ? payload.challenge_token : undefined;
      runCeremony(engine, video, new LivenessCeremony(challenges), token);
    } catch (e) {
      stopCamera();
      setPhase('error');
      setStatusText('could not start');
      setErr(
        e instanceof DOMException && e.name === 'NotAllowedError'
          ? 'Camera permission was denied. Allow the camera and try again.'
          : friendlyError(e),
      );
      if (isSessionExpired(e)) onSessionExpired?.();
    }
  }

  function runCeremony(engine: FaceEngine, video: HTMLVideoElement, ceremony: LivenessCeremony, token: string | undefined) {
    const startDescs: Float32Array[] = [];
    const endDescs: Float32Array[] = [];
    let busy = false;
    let lastDesc = 0;
    let lastT = 0;
    let lastPrompt = '';

    const tick = () => {
      if (!streamRef.current) return;
      const t = performance.now();
      if (video.readyState >= 2 && t > lastT) {
        lastT = t;
        let result;
        let s;
        try {
          result = engine.detect(video, t);
          s = frameSignal(t, result.faceLandmarks, result.faceBlendshapes?.map((c) => c.categories), video.videoWidth, video.videoHeight);
        } catch (e) {
          fail(friendlyError(e));
          return;
        }
        const p = ceremony.onFrame(s);
        const text = promptFor(p);
        if (text !== lastPrompt) {
          lastPrompt = text;
          setPrompt(text);
          setStepLabel(p.kind === 'challenge' ? `Challenge ${p.index + 1} of ${ceremony.challenges.length}` : '');
        }
        if (debug) {
          setDebugLine(
            `faces ${s.faces} yaw ${s.yaw.toFixed(2)} blink ${s.blink.toFixed(2)} size ${s.size.toFixed(2)} ` +
              `parallax [${ceremony.parallax.join(', ')}] ms [${ceremony.results.map((r) => r.ms).join(', ')}]`,
          );
        }
        if (p.kind === 'failed') {
          fail(FAIL_MESSAGES[p.reason]);
          return;
        }
        if (p.kind === 'frontal' && !busy && t - lastDesc > DESCRIPTOR_INTERVAL_MS && ceremony.wantsFrontalFrame(s)) {
          busy = true;
          const bucket = p.which === 'start' ? startDescs : endDescs;
          engine
            .describe(video, result)
            .then((d) => {
              bucket.push(d);
              lastDesc = t;
              ceremony.addFrontalFrame(t);
              busy = false;
              if (ceremony.phase.kind === 'done') void finish(ceremony, startDescs, endDescs, token);
            })
            .catch((e) => fail(friendlyError(e)));
        }
      }
      if (ceremony.phase.kind !== 'done') rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
  }

  async function finish(
    ceremony: LivenessCeremony,
    startDescs: Float32Array[],
    endDescs: Float32Array[],
    token: string | undefined,
  ) {
    stopCamera();
    if (endDescs.length > 0) {
      const gap = descriptorDistance(averageDescriptors(startDescs), averageDescriptors(endDescs));
      if (gap > SAME_FACE_MAX) {
        fail('The face at the end did not match the face at the start. Only you should be in the frame.', 'face changed');
        return;
      }
    }
    const all = [...startDescs, ...endDescs];
    const template = binarizeDescriptor(averageDescriptors(all));
    setPhase('submitting');
    setStatusText('enrolling');
    try {
      const { result } = await completeMethod(METHOD_ID, session.session_id, {
        type: 'fuzzy-extractor-response',
        payload: {
          template_b64: bytesToBase64(template),
          template_version: TEMPLATE_VERSION,
          ...(token ? { challenge_token: token, liveness: ceremony.evidence(all.length) } : {}),
        },
      });
      if (result.success) {
        setPhase('done');
        setStatusText('verified');
        onVerified();
        return;
      }
      fail(SERVER_REASONS[result.error_reason ?? ''] ?? result.error_reason ?? 'The issuer rejected this capture.', 'rejected');
    } catch (e) {
      fail(friendlyError(e), 'request failed');
      if (isSessionExpired(e)) onSessionExpired?.();
    }
  }

  return (
    <Card
      title={done ? 'Selfie check complete' : phase === 'unavailable' ? 'Selfie check unavailable' : 'Show it is you, live (no ID needed)'}
      subtitle={
        done
          ? 'Your face was checked on this phone. The issuer got only a 32-byte code derived from it.'
          : phase === 'unavailable'
            ? 'This issuer does not offer the selfie check.'
            : 'Your camera and an on-device face model check that a live person is here and that this face has not enrolled before. Your photo never leaves this phone; the issuer gets only a 32-byte code derived from your face.'
      }
      status={status}
      statusLabel={statusText}
      footer={
        <span>
          Method ID <code>{METHOD_ID}</code> · <strong>anchor</strong>
        </span>
      }
    >
      {phase === 'unavailable' && (
        <div className="row">
          <Button variant="ghost" onClick={onSkip}>
            Skip this step
          </Button>
        </div>
      )}

      {(phase === 'idle' || phase === 'error') && (
        <>
          {err && <p className="err">{err}</p>}
          <p className="prose">
            You will look at the camera, then do three short things in a random order: turn your head, blink, or bring the
            phone closer. Good light helps. The first run downloads about 12 MB of face models.
          </p>
          <div className="row">
            <Button onClick={start}>{phase === 'error' ? 'Try again' : 'Start camera'}</Button>
            <Button variant="ghost" onClick={onSkip}>
              Skip for now
            </Button>
          </div>
        </>
      )}

      {phase === 'loading' && <p className="prose">Loading the face model and camera…</p>}

      {phase === 'running' && (
        <>
          {/* Prompt above the preview so it stays in view while the person looks at the camera. */}
          <p className="step">{stepLabel || '\u00a0'}</p>
          <p className="prompt" aria-live="assertive" ref={promptRef}>
            {prompt || 'Starting…'}
          </p>
          <div className="frame">
            {/* Shown mirrored, like a mirror; detection reads the unmirrored frames. */}
            {/* eslint-disable-next-line jsx-a11y/media-has-caption */}
            <video ref={videoRef} className="preview" autoPlay playsInline muted />
            <div className="oval" aria-hidden />
          </div>
          {debug && <p className="debug">{debugLine}</p>}
          <div className="row">
            <Button
              variant="ghost"
              onClick={() => {
                stopCamera();
                setPhase('idle');
                setStatusText('ready');
              }}
            >
              Cancel
            </Button>
          </div>
        </>
      )}

      {phase === 'submitting' && (
        <>
          <div className="scanline" aria-hidden />
          <p className="prose">Checking with the issuer…</p>
        </>
      )}

      {done && (
        <div className="row">
          <Button onClick={onContinue}>Continue &rarr;</Button>
        </div>
      )}

      <style jsx>{`
        .row {
          display: flex;
          gap: var(--s-3);
          flex-wrap: wrap;
        }
        .frame {
          position: relative;
          width: 100%;
          max-width: 360px;
          margin: 0 auto;
          aspect-ratio: 3 / 4;
          max-height: 60vh;
          border-radius: var(--r-2);
          overflow: hidden;
          border: 1px solid var(--border);
          background: #000;
        }
        .preview {
          width: 100%;
          height: 100%;
          object-fit: cover;
          transform: scaleX(-1);
        }
        .oval {
          position: absolute;
          inset: 12% 18%;
          border: 2px dashed var(--accent);
          border-radius: 50%;
          pointer-events: none;
        }
        .step {
          margin: 0;
          text-align: center;
          color: var(--ink-muted);
          font-size: 13px;
          font-family: var(--f-mono);
        }
        .prompt {
          margin: 0;
          text-align: center;
          font-size: 20px;
          font-weight: 600;
        }
        .debug {
          margin: 0;
          font-family: var(--f-mono);
          font-size: 11px;
          color: var(--ink-muted);
          overflow-wrap: anywhere;
        }
        .scanline {
          height: 3px;
          background: var(--accent);
          transform-origin: left;
          animation: pulse-scan 2s var(--ease-in-out) infinite;
          border-radius: 2px;
        }
        .prose {
          margin: 0;
          color: var(--ink-muted);
          font-size: 14px;
        }
        .err {
          margin: 0;
          color: var(--danger);
          font-size: 13px;
          font-family: var(--f-mono);
        }
      `}</style>
    </Card>
  );
}
