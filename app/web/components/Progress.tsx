// Sticky step indicator. Four pills representing email → SMS → ID → credential.
// Active pill scans (animated background), completed pills are filled in
// accent, future pills are dimmed.

export type StepId = 'email' | 'sms' | 'id' | 'credential';

const ORDER: { id: StepId; label: string; short: string }[] = [
  { id: 'email', label: 'Email', short: '01' },
  { id: 'sms', label: 'SMS', short: '02' },
  { id: 'id', label: 'ID + Selfie', short: '03' },
  { id: 'credential', label: 'Credential', short: '04' },
];

export function Progress({
  current,
  completed,
  skip,
}: {
  current: StepId;
  completed: Set<StepId>;
  skip?: Set<StepId>;
}) {
  return (
    <nav className="progress" aria-label="Enrollment progress">
      <ol>
        {ORDER.map((step, idx) => {
          const isCurrent = step.id === current;
          const isDone = completed.has(step.id);
          const isSkipped = skip?.has(step.id);
          const cls = [
            'pill',
            isCurrent && 'pill--current',
            isDone && 'pill--done',
            isSkipped && 'pill--skipped',
          ]
            .filter(Boolean)
            .join(' ');
          return (
            <li key={step.id} className={cls}>
              <span className="pill__num">{step.short}</span>
              <span className="pill__label">{step.label}</span>
              {idx < ORDER.length - 1 && <span className="pill__tick" aria-hidden />}
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
          grid-template-columns: repeat(4, 1fr);
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
