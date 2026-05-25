'use client';

import { type ReactNode } from 'react';

export type Status = 'idle' | 'pending' | 'ok' | 'error';

export function StatusPill({ status, children }: { status: Status; children: ReactNode }) {
  return (
    <span className={`pill pill--${status}`} role={status === 'error' ? 'alert' : undefined}>
      <span className="dot" aria-hidden />
      <span className="text">{children}</span>
      <style jsx>{`
        .pill {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 4px 10px;
          font-family: var(--f-mono);
          font-size: 11px;
          letter-spacing: 0.06em;
          border-radius: 999px;
          border: 1px solid var(--border-strong);
          background: var(--bg-elev);
          color: var(--ink-muted);
          text-transform: uppercase;
        }
        .dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: currentColor;
        }
        .pill--idle {
          color: var(--ink-muted);
        }
        .pill--pending {
          color: var(--warning);
          border-color: rgba(255, 204, 77, 0.4);
          background: var(--warning-dim);
        }
        .pill--pending .dot {
          animation: spin 1.4s linear infinite;
          background:
            conic-gradient(from 0deg, var(--warning) 0deg, var(--warning) 90deg, transparent 91deg, transparent 360deg);
          border-radius: 50%;
        }
        .pill--ok {
          color: var(--accent);
          border-color: var(--border-accent);
          background: var(--accent-dim);
        }
        .pill--error {
          color: var(--danger);
          border-color: rgba(255, 93, 93, 0.4);
          background: var(--danger-dim);
        }
      `}</style>
    </span>
  );
}
