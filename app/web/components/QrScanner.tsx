'use client';

import { useEffect, useRef, useState } from 'react';
import { Button } from './Button';
import { Field } from './Field';

// BarcodeDetector is in Chrome on Android (and desktop Chrome on some
// platforms) but not in TypeScript's DOM lib, nor in Safari. Declared here
// minimally.
type DetectedBarcode = { rawValue: string };
type BarcodeDetectorLike = { detect(source: CanvasImageSource): Promise<DetectedBarcode[]> };
type BarcodeDetectorCtor = new (opts: { formats: string[] }) => BarcodeDetectorLike;

function barcodeDetector(): BarcodeDetectorCtor | null {
  const g = globalThis as unknown as { BarcodeDetector?: BarcodeDetectorCtor };
  return typeof g.BarcodeDetector === 'function' ? g.BarcodeDetector : null;
}

/**
 * QrScanner opens the back camera and reports every QR it decodes to
 * onScan until onScan returns true (accepted). The parent decides what a
 * valid code is. Typing the code is always offered too: it is the path on
 * browsers without BarcodeDetector (iOS Safari), and for a voucher reading
 * the code off a screen that won't scan. A typed code is weaker proximity
 * evidence than a scan, but the server cannot tell them apart anyway.
 */
export function QrScanner({
  onScan,
  typeLabel,
  disabled,
}: {
  onScan: (text: string) => boolean | Promise<boolean>;
  typeLabel: string;
  disabled?: boolean;
}) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [scanning, setScanning] = useState(false);
  const [camErr, setCamErr] = useState<string | null>(null);
  const [typed, setTyped] = useState('');
  // Feature-detected after mount: the static-export prerender has no window.
  const [supported, setSupported] = useState(false);
  useEffect(() => {
    setSupported(!!barcodeDetector() && !!navigator.mediaDevices?.getUserMedia);
  }, []);
  const onScanRef = useRef(onScan);
  onScanRef.current = onScan;

  useEffect(() => {
    if (!scanning) return;
    const Ctor = barcodeDetector();
    if (!Ctor) return;
    let stream: MediaStream | null = null;
    let stopped = false;
    let timer: number | undefined;
    const detector = new Ctor({ formats: ['qr_code'] });

    async function run() {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
        if (stopped) return;
        const v = videoRef.current;
        if (!v) return;
        v.srcObject = stream;
        await v.play();
        const tick = async () => {
          if (stopped) return;
          try {
            const codes = await detector.detect(v);
            for (const c of codes) {
              if (await onScanRef.current(c.rawValue)) {
                setScanning(false);
                return;
              }
            }
          } catch {
            // a frame that isn't ready yet; try the next one
          }
          timer = window.setTimeout(tick, 200);
        };
        void tick();
      } catch (e) {
        setCamErr(e instanceof Error ? e.message : String(e));
        setScanning(false);
      }
    }
    void run();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, [scanning]);

  async function submitTyped() {
    if (await onScanRef.current(typed)) setTyped('');
  }

  return (
    <div className="scanner">
      {supported ? (
        scanning ? (
          <>
            <video ref={videoRef} playsInline muted className="video" />
            <Button variant="ghost" onClick={() => setScanning(false)}>
              Stop camera
            </Button>
          </>
        ) : (
          <Button onClick={() => { setCamErr(null); setScanning(true); }} disabled={disabled}>
            Scan the code
          </Button>
        )
      ) : (
        <p className="note">This browser can&rsquo;t scan QR codes. Type the code shown under it instead.</p>
      )}
      {camErr && <p className="note">Camera unavailable ({camErr}). Type the code instead.</p>}
      <div className="typed">
        <Field
          label={typeLabel}
          value={typed}
          autoCapitalize="characters"
          autoComplete="off"
          spellCheck={false}
          placeholder="ABCD-1234"
          onChange={(e) => setTyped(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') void submitTyped();
          }}
        />
        <Button variant="ghost" onClick={() => void submitTyped()} disabled={disabled || typed.trim().length < 8}>
          Use typed code
        </Button>
      </div>
      <style jsx>{`
        .scanner {
          display: flex;
          flex-direction: column;
          gap: var(--s-3);
        }
        .video {
          width: 100%;
          max-height: 50vh;
          object-fit: cover;
          border-radius: var(--r-2);
          background: #000;
        }
        .note {
          margin: 0;
          font-size: 13px;
          color: var(--ink-muted);
        }
        .typed {
          display: flex;
          flex-direction: column;
          gap: var(--s-2);
        }
      `}</style>
    </div>
  );
}
