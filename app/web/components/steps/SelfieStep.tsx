'use client';

import { useEffect, useRef, useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import type { Status } from '../StatusPill';
import { beginMethod, completeMethod, type StartEnrollmentResponse } from '@/lib/api';
import {
  captureFrameFromVideo,
  deriveTemplateFromFile,
  isCameraAvailable,
  openCameraStream,
  stopCameraStream,
} from '@/lib/selfieCapture';
import { deriveTemplateFromPixels, bytesToBase64 } from '@/lib/selfieTemplate';

// fuzzy-extractor-selfie's stable plugin id, matching
// src/methods/fuzzy-extractor-selfie's MethodID constant.
const METHOD_ID = 'fuzzy-extractor-selfie';

type Phase =
  | 'idle'
  | 'camera-opening'
  | 'camera-active'
  | 'processing'
  | 'submitting'
  | 'done'
  | 'error'
  | 'unavailable';

export function SelfieStep({
  session,
  available,
  done,
  onVerified,
  onSkip,
  onContinue,
}: {
  session: StartEnrollmentResponse;
  available: boolean;
  done: boolean;
  onVerified: () => void;
  onSkip: () => void;
  onContinue: () => void;
}) {
  const [phase, setPhase] = useState<Phase>(done ? 'done' : available ? 'idle' : 'unavailable');
  const [statusText, setStatusText] = useState<string>(
    done ? 'verified' : available ? 'awaiting capture' : 'method not registered',
  );
  const [err, setErr] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const status: Status =
    phase === 'done' ? 'ok'
    : phase === 'error' ? 'error'
    : phase === 'idle' || phase === 'unavailable' ? 'idle'
    : 'pending';

  useEffect(
    () => () => {
      stopCameraStream(streamRef.current);
      streamRef.current = null;
    },
    [],
  );

  async function startCamera() {
    setErr(null);
    setPhase('camera-opening');
    setStatusText('requesting camera');
    try {
      const stream = await openCameraStream();
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }
      setPhase('camera-active');
      setStatusText('camera ready — capture when framed');
    } catch (e) {
      setPhase('error');
      setStatusText('camera unavailable');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  function stopCamera() {
    stopCameraStream(streamRef.current);
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
  }

  async function captureFromCamera() {
    if (!videoRef.current) return;
    setErr(null);
    setPhase('processing');
    setStatusText('deriving template');
    try {
      const pixels = captureFrameFromVideo(videoRef.current);
      const template = deriveTemplateFromPixels(pixels);
      stopCamera();
      await submitTemplate(template);
    } catch (e) {
      setPhase('error');
      setStatusText('capture failed');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function onFileSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ''; // allow re-selecting the same file
    if (!file) return;
    setErr(null);
    setPhase('processing');
    setStatusText('deriving template from uploaded photo');
    try {
      const template = await deriveTemplateFromFile(file);
      await submitTemplate(template);
    } catch (err2) {
      setPhase('error');
      setStatusText('failed to read image');
      setErr(err2 instanceof Error ? err2.message : String(err2));
    }
  }

  async function submitTemplate(template: Uint8Array) {
    setPhase('submitting');
    setStatusText('enrolling');
    try {
      await beginMethod(METHOD_ID, session.session_id, '');
      const { result } = await completeMethod(METHOD_ID, session.session_id, {
        type: 'fuzzy-extractor-response',
        payload: { template_b64: bytesToBase64(template) },
      });
      if (result.success) {
        setPhase('done');
        setStatusText('verified');
        onVerified();
        return;
      }
      setPhase('error');
      if (result.error_reason === 'duplicate_person_detected') {
        setStatusText('duplicate detected');
        setErr(
          'This biometric already has a Personhood identity. Each person can only enroll once with fuzzy-extractor-selfie.',
        );
      } else {
        setStatusText('rejected');
        setErr(result.error_reason || 'the server rejected this capture');
      }
    } catch (e) {
      setPhase('error');
      setStatusText('request failed');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Card
      title={done ? 'Selfie anchor complete' : phase === 'unavailable' ? 'Selfie anchor unavailable' : 'Prove you have a face (no ID needed)'}
      subtitle={
        done
          ? 'A fuzzy-extractor commitment derived from your capture anchors this credential without any central biometric database.'
          : phase === 'unavailable'
            ? 'The issuer is running without FUZZY_EXTRACTOR_ENABLED. This anchor needs no ID, bank account, or fixed address — ask the operator to enable it if you need an airdrop-test-compatible anchor.'
            : 'Capture a selfie (or upload a photo for testing). The server never sees your raw image — only a derived, one-way commitment used to check you have not already enrolled.'
      }
      status={status}
      statusLabel={statusText}
      footer={<span>Method ID <code>{METHOD_ID}</code> · strength 70 · <strong>anchor</strong></span>}
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
          <div className="row">
            {isCameraAvailable() && <Button onClick={startCamera}>Use camera</Button>}
            <Button variant="ghost" onClick={() => fileInputRef.current?.click()}>
              Upload a photo
            </Button>
            <Button variant="ghost" onClick={onSkip}>
              Skip for now
            </Button>
          </div>
        </>
      )}

      {phase === 'camera-opening' && <p className="prose">Requesting camera permission…</p>}

      {phase === 'camera-active' && (
        <>
          {/* eslint-disable-next-line jsx-a11y/media-has-caption */}
          <video ref={videoRef} className="preview" autoPlay playsInline muted />
          <div className="row">
            <Button onClick={captureFromCamera}>Capture</Button>
            <Button
              variant="ghost"
              onClick={() => {
                stopCamera();
                setPhase('idle');
                setStatusText('awaiting capture');
              }}
            >
              Cancel
            </Button>
          </div>
        </>
      )}

      {(phase === 'processing' || phase === 'submitting') && (
        <>
          <div className="scanline" aria-hidden />
          <p className="prose">{phase === 'processing' ? 'Deriving your feature vector on-device…' : 'Enrolling with the issuer…'}</p>
        </>
      )}

      {done && (
        <div className="row">
          <Button onClick={onContinue}>Continue &rarr;</Button>
        </div>
      )}

      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        data-testid="selfie-upload-input"
        style={{ display: 'none' }}
        onChange={onFileSelected}
      />

      <style jsx>{`
        .row {
          display: flex;
          gap: var(--s-3);
          flex-wrap: wrap;
        }
        .preview {
          width: 100%;
          max-height: 320px;
          border-radius: var(--r-2);
          border: 1px solid var(--border);
          background: #000;
          object-fit: cover;
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
