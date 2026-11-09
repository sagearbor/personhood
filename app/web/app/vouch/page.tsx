'use client';

import { useEffect, useState } from 'react';
import { Brand } from '@/components/Brand';
import { Button } from '@/components/Button';
import { Card } from '@/components/Card';
import { QrCode } from '@/components/QrCode';
import { QrScanner } from '@/components/QrScanner';
import type { Status } from '@/components/StatusPill';
import { ApiError, getConfig, SERVER_URL, type Credential } from '@/lib/api';
import { friendlyError } from '@/lib/errors';
import { HolderKeyLockedError, signHolderMessage } from '@/lib/holderkey';
import { listCredentials } from '@/lib/storage';
import {
  confirmMessage,
  confirmVouch,
  createOffer,
  credentialHasAnchor,
  displayCode,
  offerStatus,
  parseScan,
  vouchErrorMessage,
  type ConfirmResponse,
  type OfferResponse,
} from '@/lib/vouch';

type Phase = 'loading' | 'off' | 'no-credential' | 'ready' | 'offering' | 'showing' | 'scan-back' | 'confirming' | 'done';

function shortDID(did: string): string {
  return did.length > 24 ? `${did.slice(0, 16)}…${did.slice(-6)}` : did;
}

/**
 * The VOUCHER's side of an in-person vouch: show a code, wait for the
 * newcomer to scan it, scan the code that appears on their phone, sign.
 * Uses the credential this browser already holds; the issuer decides
 * whether it may vouch (anchored, not suspended, vouches left).
 */
export default function VouchPage() {
  const [phase, setPhase] = useState<Phase>('loading');
  const [cred, setCred] = useState<Credential | null>(null);
  const [offer, setOffer] = useState<OfferResponse | null>(null);
  const [candidate, setCandidate] = useState<string>('');
  const [result, setResult] = useState<ConfirmResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState<number>(0);
  // When the current step's code expires: the offer's deadline, then the
  // scan-back deadline once the newcomer has scanned.
  const [deadline, setDeadline] = useState<string>('');

  function reportError(e: unknown) {
    if (e instanceof HolderKeyLockedError) return setErr(e.message);
    const code = e instanceof ApiError ? e.code : undefined;
    setErr(vouchErrorMessage(code) ?? (e instanceof ApiError && e.status >= 400 && e.status < 500 ? e.message.replace(/^\d+: /, '') : friendlyError(e)));
  }

  useEffect(() => {
    (async () => {
      try {
        const cfg = await getConfig();
        if (!cfg.in_person_vouch) return setPhase('off');
        const stored = await listCredentials();
        // Newest first; an anchored credential before one without.
        stored.sort((a, b) => {
          const an = Number(credentialHasAnchor(b.credential)) - Number(credentialHasAnchor(a.credential));
          return an !== 0 ? an : b.savedAt.localeCompare(a.savedAt);
        });
        if (stored.length === 0) return setPhase('no-credential');
        setCred(stored[0].credential);
        setPhase('ready');
      } catch (e) {
        reportError(e);
        setPhase('off');
      }
    })();
  }, []);

  async function start() {
    if (!cred) return;
    setErr(null);
    setResult(null);
    setCandidate('');
    setPhase('offering');
    try {
      const o = await createOffer(cred);
      setOffer(o);
      setDeadline(o.expires_at);
      setSecondsLeft(Math.max(0, Math.round((Date.parse(o.expires_at) - Date.now()) / 1000)));
      setPhase('showing');
    } catch (e) {
      reportError(e);
      setPhase('ready');
    }
  }

  // Count down the code's lifetime and poll for the newcomer's scan.
  useEffect(() => {
    if (!offer || (phase !== 'showing' && phase !== 'scan-back')) return;
    let stop = false;
    const tick = window.setInterval(() => {
      setSecondsLeft(Math.max(0, Math.round((Date.parse(deadline) - Date.now()) / 1000)));
    }, 500);
    const poll = window.setInterval(async () => {
      try {
        const st = await offerStatus(offer.offer_code);
        if (stop) return;
        if (st.state === 'accepted' && st.candidate_did) {
          setCandidate(st.candidate_did);
          setPhase((p) => (p === 'showing' ? 'scan-back' : p));
          if (st.return_expires_at) setDeadline(st.return_expires_at);
        } else if (st.state === 'expired' || st.state === 'burned') {
          stop = true;
          setErr('The code expired before the exchange finished. Start again.');
          setOffer(null);
          setPhase('ready');
        }
      } catch {
        // transient; keep polling
      }
    }, 1500);
    return () => {
      stop = true;
      window.clearInterval(tick);
      window.clearInterval(poll);
    };
  }, [offer, phase, deadline]);

  async function onScanned(text: string): Promise<boolean> {
    if (!offer || !cred || !candidate) return false;
    const ret = parseScan(text, 'return') ?? (text.includes(':') ? null : parseScan('PHV1:R:' + text, 'return'));
    if (!ret) return false;
    setErr(null);
    setPhase('confirming');
    try {
      const sig = await signHolderMessage(confirmMessage(cred.issuer, offer.offer_code, candidate, ret));
      if (!sig) throw new Error('No signing key on this device. Vouch from the phone you enrolled on.');
      const r = await confirmVouch(offer.offer_code, ret, sig);
      setResult(r);
      setOffer(null);
      setPhase('done');
    } catch (e) {
      reportError(e);
      setPhase('scan-back');
    }
    return true;
  }

  const status: Status = phase === 'done' ? 'ok' : err ? 'error' : phase === 'showing' || phase === 'scan-back' || phase === 'offering' || phase === 'confirming' ? 'pending' : 'idle';
  const statusText =
    phase === 'done' ? 'vouch recorded'
    : phase === 'showing' ? `code live · ${secondsLeft}s`
    : phase === 'scan-back' ? `scan back · ${secondsLeft}s`
    : phase === 'off' ? 'not enabled'
    : phase === 'no-credential' ? 'no credential'
    : 'ready';

  return (
    <main className="shell">
      <Brand />
      <Card
        title="Vouch for someone you have met"
        subtitle="Only vouch for a person standing in front of you who you believe has no other credential. If they turn out to be a duplicate or a cheater, you lose the right to vouch for months and your vouches count for less."
        status={status}
        statusLabel={statusText}
        footer={
          <span>
            issuer <code>{SERVER_URL}</code>
          </span>
        }
      >
        {err && <p className="err">{err}</p>}

        {phase === 'off' && <p className="prose">This issuer does not have in-person vouching turned on.</p>}
        {phase === 'no-credential' && (
          <p className="prose">
            This browser holds no Personhood credential. <a href="/">Enrol first</a> (with the selfie step, so your credential has an anchor), then come back.
          </p>
        )}

        {phase === 'ready' && cred && (
          <>
            <p className="meta">
              Vouching as <code>{shortDID(cred.credentialSubject.id)}</code> ·{' '}
              {cred.credentialSubject.anchorMethodId ? `anchor ${cred.credentialSubject.anchorMethodId}` : 'no anchor'}
            </p>
            <div className="row">
              <Button onClick={start}>Show my vouch code</Button>
            </div>
          </>
        )}

        {phase === 'showing' && offer && (
          <div className="show">
            <p className="prose">Ask the newcomer to open the enrolment app and scan this.</p>
            <QrCode text={offer.qr_text} label={`Vouch code ${displayCode(offer.offer_code)}`} />
            <p className="code mono">{displayCode(offer.offer_code)}</p>
            <p className="meta">{offer.vouches_left} vouch{offer.vouches_left === 1 ? '' : 'es'} left this period{offer.voucher_anchored ? '' : ' · not anchored: this vouch adds points but not an anchor'}</p>
          </div>
        )}

        {phase === 'scan-back' && (
          <>
            <p className="prose">
              <code>{shortDID(candidate)}</code> scanned your code. Now scan the code on <strong>their</strong> screen.
            </p>
            <QrScanner onScan={onScanned} typeLabel="Newcomer's code" />
          </>
        )}

        {(phase === 'offering' || phase === 'confirming' || phase === 'loading') && <div className="scanline" aria-hidden />}

        {phase === 'done' && result && (
          <>
            <p className="prose">
              Vouch recorded for <code>{shortDID(result.candidate_did)}</code>. They now have {result.candidate_vouches} of {result.required}.
            </p>
            <p className="meta">
              round trip {(result.round_trip_ms / 1000).toFixed(1)} s · {result.same_network ? 'same network' : 'different networks'} · weight{' '}
              {result.weight.toFixed(2)}
            </p>
            <div className="row">
              <Button onClick={start}>Vouch for another person</Button>
            </div>
          </>
        )}
      </Card>

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
        }
        .scanline {
          height: 3px;
          background: var(--accent);
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
          word-break: break-all;
        }
        .err {
          margin: 0;
          color: var(--danger);
          font-size: 13px;
          font-family: var(--f-mono);
        }
      `}</style>
    </main>
  );
}
