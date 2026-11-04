'use client';

import { useEffect, useState } from 'react';
import { Brand } from '@/components/Brand';
import { Button } from '@/components/Button';
import { Card } from '@/components/Card';
import { ApiError, getConfig } from '@/lib/api';
import { friendlyError } from '@/lib/errors';
import { HolderKeyLockedError, signHolderMessage } from '@/lib/holderkey';
import { cancelRecovery, factorLabel, pendingRecovery, recoveryErrorMessage, untilPhrase, type RecoveryView } from '@/lib/lockout';
import { listCredentials } from '@/lib/storage';

type Item = { holderDID: string; role: 'old_key' | 'new_key'; recovery: RecoveryView; cancelMessage: string };
type Phase = 'loading' | 'off' | 'none' | 'list';

/**
 * The OLD phone's side of a recovery: is someone moving my identity to a
 * new phone? If it wasn't me, cancel it. Checks every credential this
 * browser holds.
 */
export default function RecoveryPage() {
  const [phase, setPhase] = useState<Phase>('loading');
  const [items, setItems] = useState<Item[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function load() {
    setErr(null);
    try {
      const cfg = await getConfig();
      if (!cfg.no_false_lockout) return setPhase('off');
      const dids = Array.from(new Set((await listCredentials()).map((c) => c.credential.credentialSubject.id)));
      const found: Item[] = [];
      for (const did of dids) {
        const p = await pendingRecovery(did);
        for (const r of p.pending) {
          found.push({ holderDID: did, role: p.role ?? 'old_key', recovery: r, cancelMessage: p.cancel_message ?? '' });
        }
      }
      setItems(found);
      setPhase(found.length > 0 ? 'list' : 'none');
    } catch (e) {
      setErr(friendlyError(e));
      setPhase('none');
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function cancel(it: Item) {
    setErr(null);
    try {
      const sig = await signHolderMessage(it.cancelMessage);
      if (!sig) throw new Error('This browser has no holder key to sign with.');
      await cancelRecovery(it.recovery.recovery_id, it.holderDID, sig);
      setDone(it.recovery.recovery_id);
      await load();
    } catch (e) {
      if (e instanceof HolderKeyLockedError) return setErr(e.message);
      setErr((e instanceof ApiError && recoveryErrorMessage(e)) || friendlyError(e));
    }
  }

  return (
    <main className="shell">
      <Brand />
      <Card
        title="Recovery check"
        subtitle="If someone starts moving your identity to another phone, it shows here, and this phone can stop it before it finishes."
        status={phase === 'list' ? 'error' : phase === 'loading' ? 'pending' : 'idle'}
        statusLabel={phase === 'list' ? 'action needed' : phase === 'loading' ? 'checking' : 'nothing pending'}
      >
        {err && <p className="err">{err}</p>}
        {done && <p className="ok">Recovery cancelled. Your identity stays on this phone.</p>}
        {phase === 'off' && <p className="prose">This issuer does not offer identity recovery.</p>}
        {phase === 'none' && <p className="prose">No recovery of your identity is waiting.</p>}
        {phase === 'list' &&
          items.map((it) => (
            <div className="item" key={it.recovery.recovery_id}>
              <p className="prose">
                {it.role === 'old_key'
                  ? 'Someone started moving your identity to a new phone.'
                  : 'This phone is waiting to receive an identity.'}{' '}
                It finishes <strong>{untilPhrase(it.recovery.executes_at)}</strong>. They proved:{' '}
                {it.recovery.factors.map(factorLabel).join(', ')}.
              </p>
              <p className="prose">If this was you on your new phone, do nothing. If it was not you, cancel it now.</p>
              <div className="row">
                <Button onClick={() => cancel(it)}>Cancel this recovery</Button>
              </div>
            </div>
          ))}
        <div className="row">
          <Button variant="ghost" onClick={() => void load()}>
            Check again
          </Button>
          <a href="/">back</a>
        </div>
      </Card>
      <style jsx>{`
        .item {
          display: grid;
          gap: var(--s-2);
          padding-bottom: var(--s-3);
          border-bottom: 1px solid var(--border);
        }
        .row {
          display: flex;
          gap: var(--s-3);
          align-items: center;
          flex-wrap: wrap;
        }
        .prose {
          margin: 0;
          font-size: 14px;
        }
        .err {
          margin: 0;
          color: var(--danger);
          font-size: 13px;
        }
        .ok {
          margin: 0;
          color: var(--ok, inherit);
          font-size: 14px;
        }
      `}</style>
    </main>
  );
}
