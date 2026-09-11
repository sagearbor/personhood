'use client';

import { useEffect, useRef, useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import { Field } from '../Field';
import type { Status } from '../StatusPill';
import {
  beginMethod,
  extractMagicLinkUrl,
  getSession,
  hasVerified,
  type MethodSummary,
  type StartEnrollmentResponse,
} from '@/lib/api';

// How often to ask the server whether the magic link has been clicked.
const POLL_MS = 2500;

export function EmailStep({
  session,
  method,
  done,
  devMode,
  onSent,
  onVerified,
  onContinue,
}: {
  session: StartEnrollmentResponse;
  /** The method to drive — 'email-tier' when the server advertises it, else plain 'email'. See lib/tiering.ts. */
  method: MethodSummary;
  done: boolean;
  /**
   * True when GET /v1/config reports challenge_secrets_exposed or
   * email_delivery === 'log' — i.e. this deployment cannot actually send
   * mail, so the server puts the magic link in the begin response instead.
   * Purely cosmetic: shows a "TEST MODE" notice and, once a begin response
   * actually carries magic_link_url, a tappable/copyable link. Never
   * changes the ceremony itself — the poll loop below is unchanged either
   * way.
   */
  devMode?: boolean;
  onSent: (email: string) => void;
  onVerified: () => void;
  onContinue: () => void;
}) {
  const methodID = method.id;
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [verified, setVerified] = useState(done);
  const [status, setStatus] = useState<Status>(done ? 'ok' : 'idle');
  const [statusText, setStatusText] = useState<string>(done ? 'verified' : 'awaiting input');
  const [err, setErr] = useState<string | null>(null);
  const [magicLink, setMagicLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
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
        if (hasVerified(view, methodID)) {
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
  }, [sent, verified, session.session_id, methodID]);

  async function send(action: 'send' | 'resend') {
    setErr(null);
    setStatus('pending');
    setStatusText(action === 'resend' ? 'resending' : 'sending');
    try {
      const { challenge } = await beginMethod(methodID, session.session_id, email.trim());
      // Only ever set when the server actually includes it (test/dev
      // deployments with DEV_EXPOSE_CHALLENGE_SECRETS=1) — extractMagicLinkUrl
      // returns null on any normal (no-secret) response, so this never
      // renders anything on a production deployment.
      setMagicLink(extractMagicLinkUrl(challenge));
      setCopied(false);
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

  async function copyMagicLink() {
    if (!magicLink) return;
    try {
      await navigator.clipboard.writeText(magicLink);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable/denied — the link is still visible and
      // tappable, so this is a non-fatal convenience failure.
    }
  }

  async function checkNow() {
    try {
      const view = await getSession(session.session_id);
      if (hasVerified(view, methodID)) {
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
          Method ID <code>{method.id}</code> · strength {method.strength} · supplementary
        </span>
      }
    >
      {!verified && (
        <>
          {devMode && (
            <p className="devnotice">
              <strong>TEST MODE</strong> — no email is actually sent; your magic link appears
              right here once you send it.
            </p>
          )}
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
                <Button
                  variant="ghost"
                  onClick={() => {
                    setSent(false);
                    setStatus('idle');
                    setStatusText('awaiting input');
                    setMagicLink(null);
                  }}
                >
                  Change address
                </Button>
              </>
            )}
          </div>
          {sent && magicLink && (
            <div className="magiclink">
              <a href={magicLink} target="_blank" rel="noopener noreferrer" className="magiclink__url">
                Open magic link &#8599;
              </a>
              <Button type="button" variant="ghost" size="sm" onClick={copyMagicLink}>
                {copied ? 'Copied' : 'Copy link'}
              </Button>
            </div>
          )}
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
        .devnotice {
          margin: 0;
          padding: 10px 12px;
          border: 1px solid rgba(125, 211, 252, 0.35);
          background: rgba(125, 211, 252, 0.1);
          border-radius: var(--r-2);
          color: var(--info);
          font-size: 12px;
          line-height: 1.5;
        }
        .devnotice strong {
          font-family: var(--f-mono);
          letter-spacing: 0.06em;
        }
        .magiclink {
          display: flex;
          align-items: center;
          gap: var(--s-3);
          flex-wrap: wrap;
          padding: 10px 12px;
          border: 1px dashed var(--border-accent);
          background: var(--accent-faint);
          border-radius: var(--r-2);
        }
        .magiclink__url {
          font-family: var(--f-mono);
          font-size: 12px;
          color: var(--accent);
          word-break: break-all;
          text-decoration: underline;
          text-underline-offset: 2px;
        }
      `}</style>
    </Card>
  );
}
