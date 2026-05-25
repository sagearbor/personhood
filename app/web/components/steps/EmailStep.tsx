'use client';

import { useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import { Field } from '../Field';
import type { Status } from '../StatusPill';
import { beginMethod, type StartEnrollmentResponse } from '@/lib/api';

export function EmailStep({
  session,
  done,
  onSent,
  onContinue,
}: {
  session: StartEnrollmentResponse;
  done: boolean;
  onSent: (email: string) => void;
  onContinue: () => void;
}) {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState<Status>(done ? 'ok' : 'idle');
  const [statusText, setStatusText] = useState<string>(done ? 'verified' : 'awaiting input');
  const [err, setErr] = useState<string | null>(null);

  async function send(action: 'send' | 'resend') {
    setErr(null);
    setStatus('pending');
    setStatusText(action === 'resend' ? 'resending' : 'sending');
    try {
      await beginMethod('email', session.session_id, email.trim());
      setStatus('ok');
      setStatusText('link sent');
      onSent(email.trim());
    } catch (e) {
      setStatus('error');
      setStatusText('send failed');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Card
      title={done ? 'Email verified' : 'Verify your email'}
      subtitle={
        done
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
      {!done && (
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
            hint={err || 'A one-time link will be sent.'}
          />
          <div className="row">
            <Button onClick={() => send('send')} loading={status === 'pending'} disabled={!email.includes('@')}>
              {status === 'ok' ? 'Resend link' : 'Send magic link'}
            </Button>
            {status === 'ok' && (
              <Button variant="ghost" size="md" onClick={onContinue}>
                I clicked it &rarr;
              </Button>
            )}
          </div>
          {status === 'ok' && (
            <p className="hint">
              Tap the link in the email you just received, then return to this tab and tap
              <strong> I clicked it</strong>.
            </p>
          )}
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
        .hint {
          margin: 0;
          font-size: 13px;
          color: var(--ink-muted);
        }
        .hint strong {
          color: var(--accent);
          font-weight: 600;
        }
      `}</style>
    </Card>
  );
}
