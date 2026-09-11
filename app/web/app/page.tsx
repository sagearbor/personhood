'use client';

import { useEffect, useState } from 'react';
import { Brand } from '@/components/Brand';
import { Progress, type StepId } from '@/components/Progress';
import { InviteGate } from '@/components/InviteGate';
import { EmailStep } from '@/components/steps/EmailStep';
import { SmsStep } from '@/components/steps/SmsStep';
import { IdStep } from '@/components/steps/IdStep';
import { SelfieStep } from '@/components/steps/SelfieStep';
import { CredentialStep } from '@/components/steps/CredentialStep';
import {
  startEnrollment,
  getConfig,
  ApiError,
  type StartEnrollmentResponse,
  type ConfigResponse,
  type Credential,
  SERVER_URL,
} from '@/lib/api';
import { selectEmailMethod, selectSmsMethod } from '@/lib/tiering';
import { getOrCreateHolderKeyPair } from '@/lib/holderkey';
import { readSavedInviteCode, saveInviteCode, inviteErrorMessage } from '@/lib/inviteCode';

export default function Page() {
  const [session, setSession] = useState<StartEnrollmentResponse | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [inviteCode, setInviteCode] = useState('');
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [step, setStep] = useState<StepId>('email');
  const [completed, setCompleted] = useState<Set<StepId>>(new Set());
  const [skipped, setSkipped] = useState<Set<StepId>>(new Set());
  const [credential, setCredential] = useState<Credential | null>(null);

  // Generates (or loads) the holder keypair, then asks the server for a
  // session bound to it. A holder public key is what lets the issuer bind a
  // real did:key DID + nullifierBinding onto the eventual credential (see
  // lib/holderkey.ts); on browsers without WebCrypto Ed25519 support this
  // resolves to null and enrollment proceeds exactly as it did before this
  // feature existed (v0.1 placeholder DID, no nullifierBinding).
  //
  // `code` is only sent when the deployment is invite-gated (config.
  // invite_code_required) — see the InviteGate branch below. On a gating
  // rejection (ApiError.code invite_code_required/invite_code_invalid) we
  // surface a friendly inline message on the invite gate instead of the
  // generic "cannot reach the issuer" screen.
  async function beginSession(code?: string) {
    setStartError(null);
    setInviteError(null);
    setStarting(true);
    try {
      const keyPair = await getOrCreateHolderKeyPair();
      const s = await startEnrollment({ holderPublicKeyB64: keyPair?.publicKeyB64, inviteCode: code });
      setSession(s);
      if (code) saveInviteCode(code);
    } catch (e) {
      if (e instanceof ApiError && (e.code === 'invite_code_required' || e.code === 'invite_code_invalid')) {
        setInviteError(inviteErrorMessage(e.code) ?? e.message);
      } else {
        setStartError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setStarting(false);
    }
  }

  // Boot: check whether this deployment requires an invite code (and
  // whether it's a test/dev deployment that exposes magic links on screen —
  // threaded down to EmailStep) before deciding whether to start a session
  // automatically or wait for the visitor to submit a code.
  useEffect(() => {
    let alive = true;
    (async () => {
      const cfg = await getConfig();
      if (!alive) return;
      setConfig(cfg);
      if (cfg.invite_code_required) {
        setInviteCode(readSavedInviteCode());
      } else {
        void beginSession();
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const idAvailable = !!session?.available_methods.some((m) => m.id === 'government-id-liveness');
  // fuzzy-extractor-selfie only appears in available_methods when the
  // issuer was started with FUZZY_EXTRACTOR_ENABLED=1 (see
  // src/server/server.go's BuildDependencies) — that env var IS the "flag"
  // this step is gated by; available_methods is simply how its effect is
  // exposed to the client, the same pattern IdStep already uses for
  // government-id-liveness (gated server-side by whether a Persona key is
  // configured). A round-1 deployment without the flag set never sees this
  // step or its progress pill at all.
  const selfieAvailable = !!session?.available_methods.some((m) => m.id === 'fuzzy-extractor-selfie');
  // Prefer the tiered variants (email-tier / phone-carrier-tier) whenever the
  // server advertises them; fall back to plain email/sms otherwise. See
  // lib/tiering.ts — this is the "retire the plain email/sms paths" swap
  // from STATUS.md checklist #8: the UI no longer assumes a fixed method id.
  const emailMethod = session ? selectEmailMethod(session.available_methods) : null;
  const smsMethod = session ? selectSmsMethod(session.available_methods) : null;
  const smsAvailable = !!smsMethod;
  // "Test mode": no mail credential is configured, so the server either
  // exposes challenge secrets outright (DEV_EXPOSE_CHALLENGE_SECRETS=1) or
  // is only logging mail instead of sending it. Either way, EmailStep shows
  // the on-screen magic link when the begin response actually includes one.
  const emailDevMode = !!config && (config.challenge_secrets_exposed || config.email_delivery === 'log');
  const stepOrder: StepId[] = selfieAvailable
    ? ['email', 'sms', 'id', 'selfie', 'credential']
    : ['email', 'sms', 'id', 'credential'];

  function markCompleted(id: StepId) {
    setCompleted((s) => new Set(s).add(id));
  }
  function markSkipped(id: StepId) {
    setSkipped((s) => new Set(s).add(id));
  }

  function restart() {
    setSession(null);
    setStartError(null);
    setInviteError(null);
    setStep('email');
    setCompleted(new Set());
    setSkipped(new Set());
    setCredential(null);
    // beginSession() reuses the same persisted holder keypair (see
    // lib/holderkey.ts) so a restart doesn't spuriously mint a new holder
    // identity. When the deployment is invite-gated we deliberately do NOT
    // auto-submit here — the InviteGate reappears below with `inviteCode`
    // already prefilled (component state + localStorage), so the visitor
    // taps Continue once instead of retyping the code.
    if (!config?.invite_code_required) {
      void beginSession();
    }
  }

  return (
    <main className="shell">
      <Brand />
      {session ? (
        <>
          <Progress current={step} completed={completed} skip={skipped} steps={stepOrder} />
          <div className="stage">
            {step === 'email' && emailMethod && (
              <EmailStep
                session={session}
                method={emailMethod}
                done={completed.has('email')}
                devMode={emailDevMode}
                onSent={() => {/* sent; the step polls the server until the link is clicked */}}
                onVerified={() => markCompleted('email')}
                onContinue={() => {
                  markCompleted('email');
                  // Round-1 deployments may not register SMS/phone-carrier-tier at all.
                  setStep(smsAvailable ? 'sms' : 'id');
                }}
              />
            )}
            {step === 'sms' && smsMethod && (
              <SmsStep
                session={session}
                method={smsMethod}
                done={completed.has('sms')}
                onVerified={() => markCompleted('sms')}
                onContinue={() => {
                  markCompleted('sms');
                  setStep('id');
                }}
                onSkip={() => {
                  markSkipped('sms');
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
                  setStep(selfieAvailable ? 'selfie' : 'credential');
                }}
                onContinue={() => {
                  markCompleted('id');
                  setStep(selfieAvailable ? 'selfie' : 'credential');
                }}
              />
            )}
            {step === 'selfie' && selfieAvailable && (
              <SelfieStep
                session={session}
                available={selfieAvailable}
                done={completed.has('selfie')}
                onVerified={() => markCompleted('selfie')}
                onSkip={() => {
                  markSkipped('selfie');
                  setStep('credential');
                }}
                onContinue={() => {
                  markCompleted('selfie');
                  setStep('credential');
                }}
              />
            )}
            {step === 'credential' && (
              <CredentialStep
                session={session}
                credential={credential}
                hasAnchor={
                  (completed.has('id') && !skipped.has('id')) ||
                  (completed.has('selfie') && !skipped.has('selfie'))
                }
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
      ) : config?.invite_code_required ? (
        <InviteGate
          value={inviteCode}
          onChange={setInviteCode}
          error={inviteError}
          submitting={starting}
          onSubmit={() => beginSession(inviteCode.trim())}
        />
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
