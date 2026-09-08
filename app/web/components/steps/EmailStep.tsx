'use client';

import { useEffect, useRef, useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import { Field } from '../Field';
import type { Status } from '../StatusPill';
import { beginMethod, getSession, hasVerified, type StartEnrollmentResponse } from '@/lib/api';

// How often to ask the server whether the magic link has been clicked.
const POLL_MS = 2500;

export function EmailStep({
  session,
  done,
  onSent,
  onVerified,
  onContinue,
}: {
  session: StartEnrollmentResponse;
  done: boolean;
  onSent: (email: string) => void;
  onVerified: () => void;
  onContinue: () => void;
}) {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [verified, setVerified] = useState(done);
  const [status, setStatus] = useState<Status>(done ? 'ok' : 'idle');
  const [statusText, setStatusText] = useState<string>(done ? 'verified' : 'awaiting input');
  const [err, setErr] = useState<string | null>(null);
  const pollTimer = useRef<number | null>(null);

  // Once the link is out, poll the session until the server records the
  // email ceremony as complete. The link is verified server-side when the
  // user opens it (any tab, any device) — the client never sees the token.
  useEffect(() => {
    if (!sent || verified) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const view = await getSession(session.session_id);
        if (cancelled) return;
        if (hasVerified(view, 'email')) {
          setVerified(true);
          setStatus('ok');
          setStatusText('verified');
          onVerified();
          return;
        }
      } catch (e) {
        // A transient poll failure is not fatal; keep polling.
        if (cancelled) return;
        setStatusText('waiting for click (retrying)');
      }
      pollTimer.current = window.setTimeout(tick, POLL_MS);
    };
    pollTimer.current = window.setTimeout(tick, POLL_MS);
    return () => {
      cancelled = true;
      if (pollTimer.current) window.clearTimeout(pollTimer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sent, verified, session.session_id]);

  async function send(action: 'send' | 'resend') {
    setErr(null);
    setStatus('pending');
    setStatusText(action === 'resend' ? 'resending' : 'sending');
    try {
      await beginMethod('email', session.session_id, email.trim());
      setSent(true);
      setStatus('pending');
      setStatusText('waiting for click');
      onSent(email.trim());
    } catch (e) {
      setStatus('error');
      setStatusText('send failed');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function checkNow() {
    try {
      const view = await getSession(session.session_id);
      if (hasVerified(view, 'email')) {
        setVerified(true);
        setStatus('ok');
        setStatusText('verified');
        onVerified();
      } else {
        setStatusText('not clicked yet');
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Card
      title={verified ? 'Email verified' : 'Verify your email'}
      subtitle={
        verified
          ? 'We confirmed control of your email. Continue to the next step.'
          : 'We email a magic link. You click it. We learn: that you control this inbox. We don’t learn: who you are.'
      }
      status={status}
      statusLabel={statusText}
      footer={
        <span>
          Method ID <code>email</code> · strength 8 · supplementary
        </span>
      }
    >
      {!verified && (
        <>
          <Field
            label="email address"
            type="email"
            inputMode="email"
            autoComplete="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            invalid={!!err}
            hint={err || (sent ? `Link sent to ${email.trim()}. Check spam if it takes more than a minute.` : 'A one-time link will be sent. It expires in 15 minutes.')}
            disabled={sent}
          />
          <div className="row">
            {!sent ? (
              <Button onClick={() => send('send')} loading={status === 'pending'} disabled={!email.includes('@')}>
                Send magic link
              </Button>
            ) : (
              <>
                <Button variant="ghost" onClick={checkNow}>
                  Check again
                </Button>
                <Button variant="ghost" onClick={() => send('resend')}>
                  Resend link
                </Button>
                <Button variant="ghost" onClick={() => { setSent(false); setStatus('idle'); setStatusText('awaiting input'); }}>
                  Change address
                </Button>
              </>
            )}
          </div>
          {sent && (
            <p className="hint">
              Open the email and tap the link — on this phone or any other device. This page notices
              automatically (it checks every few seconds).
            </p>
          )}
        </>
      )}
      {verified && (
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
        .hint {
          margin: 0;
          font-size: 13px;
          color: var(--ink-muted);
        }
      `}</style>
    </Card>
  );
}
