'use client';

import { useEffect, useRef, useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import type { Status } from '../StatusPill';
import {
  beginMethod,
  completeMethod,
  type ChallengeData,
  type StartEnrollmentResponse,
} from '@/lib/api';

type Phase = 'idle' | 'opening' | 'in-persona' | 'polling' | 'done' | 'error' | 'unavailable';

export function IdStep({
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
    done ? 'verified' : available ? 'awaiting start' : 'method not registered',
  );
  const [err, setErr] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<ChallengeData | null>(null);
  const pollTimer = useRef<number | null>(null);

  // Map phase to StatusPill status.
  const status: Status =
    phase === 'done' ? 'ok'
    : phase === 'error' ? 'error'
    : phase === 'idle' || phase === 'unavailable' ? 'idle'
    : 'pending';

  async function start() {
    setErr(null);
    setPhase('opening');
    setStatusText('creating inquiry');
    try {
      const { challenge: ch } = await beginMethod('government-id-liveness', session.session_id, '');
      setChallenge(ch);
      const hostedURL = ch.payload['hosted_flow_url'] as string;
      if (typeof hostedURL !== 'string' || !hostedURL.startsWith('http')) {
        throw new Error('persona response missing hosted_flow_url');
      }
      // Open Persona in a new tab so the PWA shell stays put. Persona's UI is
      // optimized for the redirect-back-to-app pattern but the new tab works
      // identically and avoids losing in-flight React state.
      window.open(hostedURL, '_blank', 'noopener,noreferrer');
      setPhase('in-persona');
      setStatusText('persona open');
      startPolling();
    } catch (e) {
      setPhase('error');
      setStatusText('failed to start');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  function startPolling() {
    stopPolling();
    setPhase('polling');
    setStatusText('waiting for persona');
    const tick = async () => {
      try {
        const res = await completeMethod('government-id-liveness', session.session_id, {
          type: 'persona-result',
          payload: {},
        });
        if (res.result.success) {
          setPhase('done');
          setStatusText('verified');
          stopPolling();
          onVerified();
          return;
        }
        // Non-success here is fine if it's still pending; failure modes have a
        // specific error_reason worth surfacing.
        const reason = res.result.error_reason || '';
        if (reason === 'pending_persona_webhook') {
          // keep polling
        } else if (reason === 'persona_declined' || reason === 'persona_inquiry_expired') {
          setPhase('error');
          setStatusText(reason === 'persona_declined' ? 'declined' : 'expired');
          setErr('Persona did not approve this attempt. Tap "Try again".');
          stopPolling();
        } else if (reason === 'persona_needs_review') {
          setPhase('error');
          setStatusText('needs review');
          setErr('Persona flagged this attempt for manual review. Tap "Try again" or skip for now.');
          stopPolling();
        }
      } catch (e) {
        setPhase('error');
        setStatusText('poll failed');
        setErr(e instanceof Error ? e.message : String(e));
        stopPolling();
      }
    };
    // First poll immediately so the user sees pulled state without delay.
    void tick();
    pollTimer.current = window.setInterval(tick, 3000);
  }

  function stopPolling() {
    if (pollTimer.current !== null) {
      window.clearInterval(pollTimer.current);
      pollTimer.current = null;
    }
  }

  // Cleanup on unmount.
  useEffect(() => () => stopPolling(), []);

  return (
    <Card
      title={done ? 'Identity anchored' : phase === 'unavailable' ? 'ID + selfie unavailable' : 'Prove you have a face'}
      subtitle={
        done
          ? 'Persona confirmed a real, present human. This is your anchor; it is what makes the credential trustworthy.'
          : phase === 'unavailable'
            ? 'The issuer is running without a Persona key. You can still get a credential, but it will lack an anchor — fine for testing the pipeline, not enough for high-stakes policies.'
            : 'Persona handles the camera flow. We never see your driver’s licence or selfie. We learn: a single real human passed the check at this moment. We don’t learn: who you are.'
      }
      status={status}
      statusLabel={statusText}
      footer={<span>Method ID <code>government-id-liveness</code> · strength 90 · <strong>anchor</strong></span>}
    >
      {phase === 'unavailable' && (
        <div className="row">
          <Button variant="ghost" onClick={onSkip}>
            Skip this step (no anchor)
          </Button>
        </div>
      )}

      {phase === 'idle' && (
        <div className="row">
          <Button onClick={start}>Open Persona</Button>
          <Button variant="ghost" onClick={onSkip}>
            Skip for now
          </Button>
        </div>
      )}

      {(phase === 'opening' || phase === 'in-persona' || phase === 'polling') && (
        <>
          <div className="scanline" aria-hidden />
          <p className="prose">
            {phase === 'in-persona' && 'Persona opened in a new tab. Complete the ID + selfie flow there.'}
            {phase === 'polling' && 'Watching for Persona to confirm. This usually takes 15-30 seconds after you finish.'}
            {phase === 'opening' && 'Spinning up a Persona inquiry.'}
          </p>
          {Boolean(challenge?.payload?.inquiry_id) && (
            <p className="meta">
              Inquiry <code>{String(challenge!.payload.inquiry_id)}</code>
            </p>
          )}
          <div className="row">
            {Boolean(challenge?.payload?.hosted_flow_url) && (
              <Button
                variant="ghost"
                onClick={() =>
                  window.open(String(challenge!.payload.hosted_flow_url), '_blank', 'noopener,noreferrer')
                }
              >
                Reopen Persona tab
              </Button>
            )}
            <Button variant="ghost" onClick={onSkip}>
              Give up &amp; skip
            </Button>
          </div>
        </>
      )}

      {phase === 'error' && (
        <>
          <p className="err">{err}</p>
          <div className="row">
            <Button onClick={start}>Try again</Button>
            <Button variant="ghost" onClick={onSkip}>
              Skip for now
            </Button>
          </div>
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
        .meta {
          margin: 0;
          font-family: var(--f-mono);
          font-size: 11px;
          color: var(--ink-faint);
          letter-spacing: 0.02em;
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
