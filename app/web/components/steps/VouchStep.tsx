'use client';

import { useEffect, useRef, useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import { QrCode } from '../QrCode';
import { QrScanner } from '../QrScanner';
import type { Status } from '../StatusPill';
import { ApiError, beginMethod, completeMethod, type StartEnrollmentResponse } from '@/lib/api';
import { friendlyError, isSessionExpired } from '@/lib/errors';
import { getOrCreateHolderKeyPair, signHolderMessage } from '@/lib/holderkey';
import {
  acceptMessage,
  acceptOffer,
  displayCode,
  GRAPH_METHOD_ID,
  IN_PERSON_METHOD_ID,
  offerStatus,
  parseScan,
  vouchErrorMessage,
  type AcceptResponse,
} from '@/lib/vouch';

type Phase = 'loading' | 'scan' | 'accepting' | 'showing' | 'checking' | 'done' | 'unavailable';

/**
 * VouchStep is the NEWCOMER's side of an in-person vouch: scan the
 * voucher's code, show a code back, repeat with each voucher until the
 * issuer counts enough. It completes in-person-vouch (the anchor) when the
 * issuer offers it, else social-vouching-graph (supplementary points).
 */
export function VouchStep({
  session,
  onSessionExpired,
  done,
  onVerified,
  onSkip,
  onContinue,
}: {
  session: StartEnrollmentResponse;
  onSessionExpired?: () => void;
  done: boolean;
  onVerified: () => void;
  onSkip: () => void;
  onContinue: () => void;
}) {
  const methodID = session.available_methods.some((m) => m.id === IN_PERSON_METHOD_ID) ? IN_PERSON_METHOD_ID : GRAPH_METHOD_ID;
  const isAnchor = methodID === IN_PERSON_METHOD_ID;
  const [phase, setPhase] = useState<Phase>(done ? 'done' : 'loading');
  const [required, setRequired] = useState<number>(0);
  const [have, setHave] = useState<number>(0);
  const [accepted, setAccepted] = useState<AcceptResponse | null>(null);
  const [offerCode, setOfferCode] = useState<string>('');
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const alive = useRef(true);

  function reportError(e: unknown) {
    const code = e instanceof ApiError ? e.code : undefined;
    const msg = vouchErrorMessage(code) ?? (e instanceof ApiError && e.status >= 400 && e.status < 500 ? e.message.replace(/^\d+: /, '') : friendlyError(e));
    setErr(msg);
    if (isSessionExpired(e)) onSessionExpired?.();
  }

  useEffect(() => {
    alive.current = true;
    if (done) return;
    (async () => {
      try {
        const { challenge } = await beginMethod(methodID, session.session_id, '');
        const p = challenge.payload;
        setRequired(Number(p.required ?? p.required_vouches ?? 0));
        await check();
      } catch (e) {
        if (!alive.current) return;
        setPhase('unavailable');
        reportError(e);
      }
    })();
    return () => {
      alive.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // check asks the issuer whether the vouches so far are enough.
  async function check() {
    setPhase('checking');
    const { result } = await completeMethod(methodID, session.session_id, { type: 'vouch-poll', payload: {} });
    if (!alive.current) return;
    if (result.success) {
      setPhase('done');
      onVerified();
      return;
    }
    const reason = result.error_reason ?? '';
    const m = /have=(\d+)\/(\d+)/.exec(reason);
    if (m) {
      setHave(Number(m[1]));
      setRequired(Number(m[2]));
      setNote(null);
    } else if (reason.startsWith('prerequisite_missing:')) {
      setNote('The issuer also needs the selfie step from this session before vouches can anchor your credential. Go back and do it, or keep collecting vouches first.');
    } else if (reason) {
      setNote(reason);
    }
    setPhase('scan');
  }

  async function onScanned(text: string): Promise<boolean> {
    const code = parseScan(text, 'offer') ?? (text.includes(':') ? null : parseScan('PHV1:O:' + text, 'offer'));
    if (!code) return false;
    setErr(null);
    setPhase('accepting');
    try {
      const pair = await getOrCreateHolderKeyPair();
      if (!pair) throw new Error('This browser cannot hold a signing key, so it cannot be vouched for.');
      const sig = await signHolderMessage(acceptMessage(session.issuer_did, code, session.holder_did));
      if (!sig) throw new Error('No signing key on this device.');
      const acc = await acceptOffer(code, pair.publicKeyB64, sig);
      if (!alive.current) return true;
      setOfferCode(code);
      setAccepted(acc);
      setPhase('showing');
    } catch (e) {
      setPhase('scan');
      reportError(e);
    }
    return true;
  }

  // While our code is on screen, poll until the voucher confirms.
  useEffect(() => {
    if (phase !== 'showing' || !offerCode) return;
    let stop = false;
    const timer = window.setInterval(async () => {
      try {
        const st = await offerStatus(offerCode);
        if (stop) return;
        if (st.state === 'confirmed') {
          stop = true;
          window.clearInterval(timer);
          try {
            await check();
          } catch (e) {
            setPhase('scan');
            reportError(e);
          }
        } else if (st.state === 'expired' || st.state === 'burned') {
          stop = true;
          window.clearInterval(timer);
          setAccepted(null);
          setPhase('scan');
          setErr('The voucher did not scan your code in time. Ask them to start again.');
        }
      } catch {
        // transient; keep polling
      }
    }, 1500);
    return () => {
      stop = true;
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, offerCode]);

  const status: Status = phase === 'done' ? 'ok' : phase === 'unavailable' ? 'idle' : err ? 'error' : phase === 'scan' ? 'idle' : 'pending';
  const statusText =
    phase === 'done' ? 'vouched'
    : phase === 'unavailable' ? 'unavailable'
    : required ? `${have} of ${required} vouches`
    : 'starting';

  return (
    <Card
      title={done || phase === 'done' ? 'Vouched for in person' : 'Get vouched in person'}
      subtitle={
        phase === 'done'
          ? isAnchor
            ? 'Enough people who already hold an anchored credential met you and vouched. This anchors your credential.'
            : 'Enough members vouched for you. This adds supplementary points to your credential.'
          : `Meet ${required || 'a few'} people who already have a Personhood credential. Each one shows you a code on their phone: scan it, then let them scan the code that appears on yours. Both phones need to be online.`
      }
      status={status}
      statusLabel={statusText}
      footer={
        <span>
          Method ID <code>{methodID}</code> · {isAnchor ? 'strength 55 · ' : 'strength 35 · '}
          <strong>{isAnchor ? 'anchor' : 'supplementary'}</strong>
        </span>
      }
    >
      {err && <p className="err">{err}</p>}
      {note && <p className="prose">{note}</p>}

      {phase === 'scan' && (
        <>
          {have > 0 && <p className="prose">{have} of {required} so far. Next voucher, please.</p>}
          <QrScanner onScan={onScanned} typeLabel="Voucher's code" />
        </>
      )}

      {(phase === 'loading' || phase === 'checking' || phase === 'accepting') && <div className="scanline" aria-hidden />}

      {phase === 'showing' && accepted && (
        <div className="show">
          <p className="prose">Now let the voucher scan this code with their phone.</p>
          <QrCode text={accepted.qr_text} label={`Your code ${displayCode(accepted.return_code)}`} />
          <p className="code mono">{displayCode(accepted.return_code)}</p>
          <p className="meta">Waiting for the voucher to confirm…</p>
        </div>
      )}

      {phase === 'done' && (
        <div className="row">
          <Button onClick={onContinue}>Continue &rarr;</Button>
        </div>
      )}
      {phase !== 'done' && (
        <div className="row">
          <Button variant="ghost" onClick={onSkip}>
            {phase === 'unavailable' ? 'Skip this step' : 'Skip for now'}
          </Button>
        </div>
      )}

      <style jsx>{`
        .row {
          display: flex;
          gap: var(--s-3);
          flex-wrap: wrap;
        }
        .show {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: var(--s-3);
          text-align: center;
        }
        .code {
          margin: 0;
          font-size: 28px;
          letter-spacing: 0.12em;
          color: var(--ink);
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
