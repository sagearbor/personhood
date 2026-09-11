// Sticky step indicator. Four pills representing email → SMS → ID → credential.
// Active pill scans (animated background), completed pills are filled in
// accent, future pills are dimmed.

export type StepId = 'email' | 'sms' | 'id' | 'selfie' | 'credential';

const DEFAULT_ORDER: StepId[] = ['email', 'sms', 'id', 'credential'];

const LABELS: Record<StepId, { label: string; short: string }> = {
  email: { label: 'Email', short: '01' },
  sms: { label: 'SMS', short: '02' },
  id: { label: 'ID + Selfie', short: '03' },
  // "selfie" (fuzzy-extractor-selfie) is only inserted into the order when
  // the issuer advertises the method (see app/page.tsx) — round-1
  // deployments without FUZZY_EXTRACTOR_ENABLED never render this pill, so
  // their 4-step layout is byte-for-byte unchanged from before this step
  // existed.
  selfie: { label: 'Selfie anchor', short: '04' },
  credential: { label: 'Credential', short: '05' },
};

/**
 * steps overrides the pill order (used to insert the optional "selfie"
 * step only when fuzzy-extractor-selfie is registered — see app/page.tsx);
 * defaults to the original fixed 4-step order otherwise.
 */
export function Progress({
  current,
  completed,
  skip,
  steps,
}: {
  current: StepId;
  completed: Set<StepId>;
  skip?: Set<StepId>;
  steps?: StepId[];
}) {
  const order = steps && steps.length > 0 ? steps : DEFAULT_ORDER;
  return (
    <nav className="progress" aria-label="Enrollment progress">
      <ol style={{ gridTemplateColumns: `repeat(${order.length}, 1fr)` }}>
        {order.map((id, idx) => {
          const isCurrent = id === current;
          const isDone = completed.has(id);
          const isSkipped = skip?.has(id);
          const cls = [
            'pill',
            isCurrent && 'pill--current',
            isDone && 'pill--done',
            isSkipped && 'pill--skipped',
          ]
            .filter(Boolean)
            .join(' ');
          return (
            <li key={id} className={cls}>
              <span className="pill__num">{LABELS[id].short}</span>
              <span className="pill__label">{LABELS[id].label}</span>
              {idx < order.length - 1 && <span className="pill__tick" aria-hidden />}
            </li>
          );
        })}
      </ol>
      <style jsx>{`
        .progress {
          padding: var(--s-3) var(--s-5);
          border-bottom: 1px solid var(--border);
          background: linear-gradient(180deg, var(--bg) 0%, rgba(8, 9, 12, 0.92) 100%);
          backdrop-filter: blur(6px);
          position: sticky;
          top: 0;
          z-index: 10;
        }
        ol {
          display: grid;
          /* grid-template-columns is set inline (see the <ol> element above)
             so the pill count can vary — repeat(4, 1fr) by default, 5 when
             the optional "selfie" step is inserted. */
          gap: var(--s-1);
          list-style: none;
          padding: 0;
          margin: 0;
        }
        .pill {
          position: relative;
          display: flex;
          flex-direction: column;
          gap: 2px;
          padding: 8px 6px 10px;
          border: 1px solid var(--border);
          border-radius: var(--r-2);
          background: var(--bg-elev);
          font-family: var(--f-mono);
          transition: border-color var(--t-base) var(--ease-out), background var(--t-base) var(--ease-out);
          overflow: hidden;
        }
        .pill__num {
          font-size: 10px;
          letter-spacing: 0.12em;
          color: var(--ink-faint);
        }
        .pill__label {
          font-size: 11px;
          letter-spacing: 0.04em;
          color: var(--ink-muted);
        }
        .pill__tick {
          position: absolute;
          bottom: 0;
          left: 0;
          right: 0;
          height: 2px;
          background: var(--border);
        }
        .pill--current {
          border-color: var(--accent);
          background: linear-gradient(180deg, var(--bg-elev), var(--accent-faint));
        }
        .pill--current .pill__num {
          color: var(--accent);
        }
        .pill--current .pill__label {
          color: var(--ink);
        }
        .pill--current .pill__tick {
          background: var(--accent);
          transform-origin: left;
          animation: pulse-scan 1.6s var(--ease-in-out) infinite;
        }
        .pill--done {
          border-color: var(--border-accent);
          background: var(--bg-elev);
        }
        .pill--done .pill__num {
          color: var(--accent);
        }
        .pill--done .pill__num::after {
          content: ' ✓';
        }
        .pill--done .pill__label {
          color: var(--ink);
        }
        .pill--done .pill__tick {
          background: var(--accent);
        }
        .pill--skipped {
          opacity: 0.5;
        }
        .pill--skipped .pill__label::after {
          content: ' (skipped)';
          color: var(--ink-faint);
        }
      `}</style>
    </nav>
  );
}
