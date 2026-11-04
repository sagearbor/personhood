'use client';

import { useEffect, useState } from 'react';
import { Button } from './Button';
import { ApiError, completeMethod, type FaceMatchRouting, type NextStep, type StartEnrollmentResponse } from '@/lib/api';
import { friendlyError } from '@/lib/errors';
import {
  completeRecovery,
  declineFaceMatch,
  forgetRecovery,
  recoveryErrorMessage,
  rememberRecovery,
  requestReview,
  startRecovery,
  untilPhrase,
  type RecoveryView,
} from '@/lib/lockout';

type View =
  | { kind: 'choose' }
  | { kind: 'busy' }
  | { kind: 'steps'; message: string; steps: NextStep[] }
  | { kind: 'pending'; recovery: { id: string; executes_at: string } }
  | { kind: 'declined'; extra: number; steps: NextStep[] }
  | { kind: 'review'; id: string };

/**
 * Shown when the selfie matched someone already enrolled (or when this
 * phone has a recovery waiting). Nobody is refused for a face alone: the
 * person picks "this is me" (recovery), "not me" (another anchor) or a
 * manual review.
 */
export function FaceMatchPanel({
  session,
  routing,
  resume,
  onRecovered,
  onDeclined,
}: {
  session: StartEnrollmentResponse;
  routing: FaceMatchRouting | null;
  /** A recovery this phone started earlier, to finish now. */
  resume?: { id: string; executes_at: string } | null;
  /**
   * The session now holds an anchor: the recovered identity's face, or an
   * approved manual review.
   */
  onRecovered: () => void;
  /** The person said the match is not them; continue with other steps. */
  onDeclined: () => void;
}) {
  const [view, setView] = useState<View>(resume ? { kind: 'pending', recovery: resume } : { kind: 'choose' });
  const [err, setErr] = useState<string | null>(null);
  const [, tick] = useState(0);
  const has = (action: string) => !!routing?.options.some((o) => o.action === action);

  // Re-render once a minute so the countdown and the Finish button update.
  useEffect(() => {
    if (view.kind !== 'pending') return;
    const t = setInterval(() => tick((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, [view.kind]);

  function report(e: unknown) {
    if (e instanceof ApiError) {
      const msg = recoveryErrorMessage(e);
      if (e.nextSteps && e.nextSteps.length > 0) {
        setView({ kind: 'steps', message: msg ?? friendlyError(e), steps: e.nextSteps });
        return;
      }
      if (msg) {
        setErr(msg);
        return;
      }
    }
    setErr(friendlyError(e));
  }

  async function recover() {
    setErr(null);
    setView({ kind: 'busy' });
    try {
      const r: RecoveryView = await startRecovery(session.session_id);
      const rec = { id: r.recovery_id, executes_at: r.executes_at };
      rememberRecovery(session.holder_did, rec);
      setView({ kind: 'pending', recovery: rec });
    } catch (e) {
      setView({ kind: 'choose' });
      report(e);
    }
  }

  async function finish(id: string) {
    setErr(null);
    try {
      await completeRecovery(id, session.session_id);
      forgetRecovery(session.holder_did);
      onRecovered();
    } catch (e) {
      if (e instanceof ApiError && (e.code === 'recovery_closed' || e.code === 'recovery_not_found')) {
        forgetRecovery(session.holder_did);
        setView({ kind: 'choose' });
      }
      report(e);
    }
  }

  async function notMe() {
    setErr(null);
    setView({ kind: 'busy' });
    try {
      const d = await declineFaceMatch(session.session_id);
      setView({ kind: 'declined', extra: d.extra_vouches, steps: d.options });
    } catch (e) {
      setView({ kind: 'choose' });
      report(e);
    }
  }

  async function review() {
    setErr(null);
    setView({ kind: 'busy' });
    try {
      // An operator may already have approved this phone's review: then the
      // operator-review anchor completes and the person continues.
      const { result } = await completeMethod('operator-review', session.session_id, { type: 'operator-review', payload: {} });
      if (result.success) {
        onRecovered();
        return;
      }
      const r = await requestReview(session.session_id, 'face_match', 'Selfie matched an enrolled person.');
      setView({ kind: 'review', id: r.review_id });
    } catch (e) {
      if (e instanceof ApiError && e.code === 'review_open' && typeof e.details?.review_id === 'string') {
        setView({ kind: 'review', id: e.details.review_id });
        return;
      }
      setView({ kind: 'choose' });
      report(e);
    }
  }

  return (
    <div className="fm" role="region" aria-label="Face match">
      {err && <p className="err">{err}</p>}

      {view.kind === 'choose' && (
        <>
          <p className="lead">{routing?.message ?? 'This face looks like someone who is already enrolled.'}</p>
          <div className="opts">
            {has('recover') && (
              <div className="opt">
                <Button onClick={recover}>This is me: recover my identity</Button>
                <p className="hint">For a new, reset or replaced phone. Needs one more proof, then a waiting period during which your old phone can cancel.</p>
              </div>
            )}
            {has('other_anchor') && (
              <div className="opt">
                <Button variant="ghost" onClick={notMe}>
                  Not me (twin or look-alike)
                </Button>
                <p className="hint">Continue another way, such as in-person vouching. You get your own identity, not theirs.</p>
              </div>
            )}
            {has('manual_review') && (
              <div className="opt">
                <Button variant="ghost" onClick={review}>
                  Ask a person to review
                </Button>
              </div>
            )}
          </div>
        </>
      )}

      {view.kind === 'busy' && <p className="hint">Asking the issuer…</p>}

      {view.kind === 'steps' && (
        <>
          <p className="lead">{view.message}</p>
          <ul className="steps">
            {view.steps.map((s) => (
              <li key={s.action}>{s.description}</li>
            ))}
          </ul>
          <div className="row">
            <Button variant="ghost" onClick={() => setView({ kind: 'choose' })}>
              Back
            </Button>
            {view.steps.some((s) => s.action === 'manual_review') && (
              <Button variant="ghost" onClick={review}>
                Ask a person to review
              </Button>
            )}
          </div>
        </>
      )}

      {view.kind === 'pending' && (
        <>
          <p className="lead">
            Recovery started. It can finish <strong>{untilPhrase(view.recovery.executes_at)}</strong> (
            {new Date(view.recovery.executes_at).toLocaleString()}).
          </p>
          <p className="hint">
            Until then your old phone can cancel it, so nobody can quietly take your identity. Come back to this page on
            this phone and tap Finish.
          </p>
          <div className="row">
            <Button onClick={() => finish(view.recovery.id)} disabled={Date.parse(view.recovery.executes_at) > Date.now()}>
              Finish recovery
            </Button>
          </div>
        </>
      )}

      {view.kind === 'declined' && (
        <>
          <p className="lead">Understood: your selfie is not used, and you will get your own identity.</p>
          <ul className="steps">
            {view.steps.map((s) => (
              <li key={s.action}>
                {s.action === 'other_anchor' && view.extra > 0
                  ? `Continue with another way to prove you are you. In-person vouching asks for ${view.extra} more vouchers than usual.`
                  : s.description}
              </li>
            ))}
          </ul>
          <div className="row">
            <Button onClick={onDeclined}>Continue &rarr;</Button>
          </div>
        </>
      )}

      {view.kind === 'review' && (
        <p className="lead">
          Review requested (<code>{view.id.slice(0, 8)}</code>). A person at the issuer will look at it. Once it is approved,
          come back on this phone, take the selfie again and tap &ldquo;Ask a person to review&rdquo;: the approval is
          used and you continue.
        </p>
      )}

      <style jsx>{`
        .fm {
          display: grid;
          gap: var(--s-3);
        }
        .lead {
          margin: 0;
          font-size: 15px;
        }
        .opts {
          display: grid;
          gap: var(--s-3);
        }
        .opt {
          display: grid;
          gap: 4px;
        }
        .hint {
          margin: 0;
          color: var(--ink-muted);
          font-size: 13px;
        }
        .steps {
          margin: 0;
          padding-left: 1.2em;
          font-size: 14px;
          display: grid;
          gap: 6px;
        }
        .row {
          display: flex;
          gap: var(--s-3);
          flex-wrap: wrap;
        }
        .err {
          margin: 0;
          color: var(--danger);
          font-size: 13px;
        }
      `}</style>
    </div>
  );
}
