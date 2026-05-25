'use client';

import { useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import { Field } from '../Field';
import type { Status } from '../StatusPill';
import { beginMethod, completeMethod, type StartEnrollmentResponse } from '@/lib/api';

export function SmsStep({
  session,
  done,
  onVerified,
  onContinue,
}: {
  session: StartEnrollmentResponse;
  done: boolean;
  onVerified: () => void;
  onContinue: () => void;
}) {
  const [phone, setPhone] = useState('');
  const [code, setCode] = useState('');
  const [status, setStatus] = useState<Status>(done ? 'ok' : 'idle');
  const [statusText, setStatusText] = useState<string>(done ? 'verified' : 'awaiting input');
  const [stage, setStage] = useState<'enter-phone' | 'enter-code'>(done ? 'enter-code' : 'enter-phone');
  const [err, setErr] = useState<string | null>(null);

  async function sendCode() {
    setErr(null);
    setStatus('pending');
    setStatusText('sending code');
    try {
      await beginMethod('sms', session.session_id, phone.trim());
      setStatus('ok');
      setStatusText('code sent');
      setStage('enter-code');
    } catch (e) {
      setStatus('error');
      setStatusText('send failed');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function submitCode() {
    setErr(null);
    setStatus('pending');
    setStatusText('verifying');
    try {
      const res = await completeMethod('sms', session.session_id, {
        type: 'otp',
        payload: { phone_number: phone.trim(), code: code.trim() },
      });
      if (res.result.success) {
        setStatus('ok');
        setStatusText('verified');
        onVerified();
      } else {
        setStatus('error');
        setStatusText('wrong code');
        setErr(res.result.error_reason || 'verification failed');
      }
    } catch (e) {
      setStatus('error');
      setStatusText('error');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Card
      title={done ? 'Phone verified' : 'Verify your phone'}
      subtitle={
        done
          ? 'We confirmed control of your phone number. Continue to the next step.'
          : 'We text a 6-digit code. You type it back. We learn: you control a real phone line. We don’t learn: who you are.'
      }
      status={status}
      statusLabel={statusText}
      footer={<span>Method ID <code>sms</code> · strength 12 · supplementary</span>}
    >
      {!done && stage === 'enter-phone' && (
        <>
          <Field
            label="phone number"
            type="tel"
            inputMode="tel"
            autoComplete="tel"
            placeholder="+1 555 123 4567"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            invalid={!!err}
            hint={err || 'Use E.164 format: a leading + and country code.'}
          />
          <div className="row">
            <Button onClick={sendCode} loading={status === 'pending'} disabled={!phone.trim().startsWith('+')}>
              Text me a code
            </Button>
          </div>
        </>
      )}

      {!done && stage === 'enter-code' && (
        <>
          <Field
            label="6-digit code"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="000000"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            invalid={!!err}
            hint={err || `Sent to ${phone}. Codes expire in 5 minutes.`}
          />
          <div className="row">
            <Button onClick={submitCode} loading={status === 'pending'} disabled={code.length !== 6}>
              Verify
            </Button>
            <Button variant="ghost" onClick={sendCode}>
              Resend code
            </Button>
            <Button variant="ghost" onClick={() => { setStage('enter-phone'); setCode(''); }}>
              Change number
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
      `}</style>
    </Card>
  );
}
