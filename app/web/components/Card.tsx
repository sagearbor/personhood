'use client';

import { type ReactNode } from 'react';
import { StatusPill, type Status } from './StatusPill';

export function Card({
  title,
  subtitle,
  status,
  statusLabel,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  status: Status;
  statusLabel: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <section className="card" aria-busy={status === 'pending'}>
      <div className="card__head">
        <div className="card__titles">
          <h2 className="card__title">{title}</h2>
          {subtitle ? <p className="card__sub">{subtitle}</p> : null}
        </div>
        <StatusPill status={status}>{statusLabel}</StatusPill>
      </div>
      <div className="card__body">{children}</div>
      {footer ? <div className="card__foot">{footer}</div> : null}
      <style jsx>{`
        .card {
          margin: var(--s-5);
          padding: var(--s-5);
          background: var(--bg-elev);
          border: 1px solid var(--border);
          border-radius: var(--r-3);
          box-shadow: 0 1px 0 rgba(255, 255, 255, 0.02) inset, 0 24px 60px -32px rgba(0, 0, 0, 0.8);
          animation: fade-up var(--t-slow) var(--ease-out) both;
          animation-delay: 80ms;
        }
        .card__head {
          display: flex;
          gap: var(--s-3);
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: var(--s-4);
        }
        .card__title {
          font-family: var(--f-sans);
          font-weight: 600;
          font-size: 22px;
          line-height: 1.2;
          margin: 0 0 4px;
          letter-spacing: -0.01em;
        }
        .card__sub {
          margin: 0;
          font-size: 14px;
          color: var(--ink-muted);
        }
        .card__body {
          display: flex;
          flex-direction: column;
          gap: var(--s-4);
        }
        .card__foot {
          margin-top: var(--s-5);
          padding-top: var(--s-4);
          border-top: 1px dashed var(--border);
          color: var(--ink-faint);
          font-size: 12px;
          font-family: var(--f-mono);
          letter-spacing: 0.02em;
        }
      `}</style>
    </section>
  );
}
