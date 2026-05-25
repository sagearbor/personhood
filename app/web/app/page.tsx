'use client';

import { useEffect, useState } from 'react';
import { Brand } from '@/components/Brand';
import { Progress, type StepId } from '@/components/Progress';
import { EmailStep } from '@/components/steps/EmailStep';
import { SmsStep } from '@/components/steps/SmsStep';
import { IdStep } from '@/components/steps/IdStep';
import { CredentialStep } from '@/components/steps/CredentialStep';
import { startEnrollment, type StartEnrollmentResponse, type Credential, SERVER_URL } from '@/lib/api';

export default function Page() {
  const [session, setSession] = useState<StartEnrollmentResponse | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  const [step, setStep] = useState<StepId>('email');
  const [completed, setCompleted] = useState<Set<StepId>>(new Set());
  const [skipped, setSkipped] = useState<Set<StepId>>(new Set());
  const [credential, setCredential] = useState<Credential | null>(null);

  // Boot: ask the server for a session.
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const s = await startEnrollment({});
        if (!alive) return;
        setSession(s);
      } catch (e) {
        if (!alive) return;
        setStartError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const idAvailable = !!session?.available_methods.some((m) => m.id === 'government-id-liveness');

  function markCompleted(id: StepId) {
    setCompleted((s) => new Set(s).add(id));
  }
  function markSkipped(id: StepId) {
    setSkipped((s) => new Set(s).add(id));
  }

  function restart() {
    setSession(null);
    setStartError(null);
    setStep('email');
    setCompleted(new Set());
    setSkipped(new Set());
    setCredential(null);
    // Triggers the boot effect again.
    startEnrollment({}).then(setSession).catch((e) => setStartError(String(e)));
  }

  return (
    <main className="shell">
      <Brand />
      {session ? (
        <>
          <Progress current={step} completed={completed} skip={skipped} />
          <div className="stage">
            {step === 'email' && (
              <EmailStep
                session={session}
                done={completed.has('email')}
                onSent={() => {/* sent; user must click link to verify */}}
                onContinue={() => {
                  markCompleted('email');
                  setStep('sms');
                }}
              />
            )}
            {step === 'sms' && (
              <SmsStep
                session={session}
                done={completed.has('sms')}
                onVerified={() => markCompleted('sms')}
                onContinue={() => {
                  markCompleted('sms');
                  setStep('id');
                }}
              />
            )}
            {step === 'id' && (
              <IdStep
                session={session}
                available={idAvailable}
                done={completed.has('id')}
                onVerified={() => markCompleted('id')}
                onSkip={() => {
                  markSkipped('id');
                  setStep('credential');
                }}
                onContinue={() => {
                  markCompleted('id');
                  setStep('credential');
                }}
              />
            )}
            {step === 'credential' && (
              <CredentialStep
                session={session}
                credential={credential}
                hasAnchor={completed.has('id') && !skipped.has('id')}
                onIssued={(c) => {
                  setCredential(c);
                  markCompleted('credential');
                }}
                onRestart={restart}
              />
            )}
          </div>
          <footer className="foot">
            <span>
              server <code>{SERVER_URL}</code>
            </span>
            <span>
              issuer <code className="trunc">{session.issuer_did}</code>
            </span>
          </footer>
        </>
      ) : startError ? (
        <div className="boot boot--err">
          <h2>Cannot reach the issuer</h2>
          <p className="err">{startError}</p>
          <p className="muted">
            Expected the server at <code>{SERVER_URL}</code>. Start it with{' '}
            <code>go run ./src/server/cmd/server</code> and set
            <code> NEXT_PUBLIC_PERSONHOOD_SERVER_URL</code> if it is hosted elsewhere.
          </p>
        </div>
      ) : (
        <div className="boot">
          <span className="cursor mono" aria-hidden>
            _
          </span>
          <p className="muted">Reaching the issuer…</p>
        </div>
      )}

      <style jsx>{`
        .shell {
          position: relative;
          max-width: 560px;
          margin: 0 auto;
          min-height: 100dvh;
          display: flex;
          flex-direction: column;
          z-index: 1;
        }
        .stage {
          flex: 1;
          display: flex;
          flex-direction: column;
        }
        .boot {
          padding: var(--s-7) var(--s-5);
          text-align: center;
          color: var(--ink-muted);
          display: flex;
          flex-direction: column;
          gap: var(--s-3);
          align-items: center;
          flex: 1;
          justify-content: center;
        }
        .boot--err {
          color: var(--danger);
          text-align: left;
          align-items: stretch;
        }
        .boot h2 {
          margin: 0;
          font-size: 18px;
          color: var(--ink);
        }
        .boot p {
          margin: 0;
        }
        .cursor {
          font-size: 32px;
          color: var(--accent);
          animation: cursor-blink 1s steps(2) infinite;
        }
        .muted {
          color: var(--ink-muted);
          font-size: 14px;
        }
        .err {
          font-family: var(--f-mono);
          font-size: 13px;
          color: var(--danger);
          word-break: break-all;
        }
        .foot {
          display: flex;
          justify-content: space-between;
          gap: var(--s-3);
          padding: var(--s-3) var(--s-5) calc(var(--s-3) + env(safe-area-inset-bottom));
          border-top: 1px solid var(--border);
          font-family: var(--f-mono);
          font-size: 11px;
          color: var(--ink-faint);
          letter-spacing: 0.04em;
        }
        .foot code {
          color: var(--ink-muted);
        }
        .trunc {
          max-width: 18ch;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          display: inline-block;
          vertical-align: bottom;
        }
        @media (min-width: 600px) {
          .shell {
            border-left: 1px solid var(--border);
            border-right: 1px solid var(--border);
          }
        }
      `}</style>
    </main>
  );
}
