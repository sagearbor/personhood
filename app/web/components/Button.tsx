'use client';

import { type ButtonHTMLAttributes, forwardRef } from 'react';

type Variant = 'primary' | 'ghost' | 'danger';
type Size = 'md' | 'sm';

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'md', loading, children, disabled, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      {...props}
      className={`btn btn--${variant} btn--${size} ${loading ? 'btn--loading' : ''}`}
      disabled={disabled || loading}
    >
      {loading ? <span className="btn__spinner" aria-hidden /> : null}
      <span className="btn__label">{children}</span>
      <style jsx>{`
        .btn {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          font-family: var(--f-mono);
          letter-spacing: 0.06em;
          text-transform: uppercase;
          font-weight: 600;
          border-radius: var(--r-2);
          transition: transform var(--t-fast) var(--ease-out), background var(--t-fast) var(--ease-out), border-color var(--t-fast) var(--ease-out), opacity var(--t-fast) var(--ease-out);
        }
        .btn:active:not(:disabled) {
          transform: translateY(1px);
        }
        .btn:disabled {
          opacity: 0.5;
        }
        .btn--md {
          padding: 14px 18px;
          font-size: 13px;
        }
        .btn--sm {
          padding: 8px 12px;
          font-size: 11px;
        }
        .btn--primary {
          background: var(--accent);
          color: var(--accent-ink);
          border: 1px solid var(--accent);
        }
        .btn--primary:hover:not(:disabled) {
          background: #dafe5b;
        }
        .btn--ghost {
          background: transparent;
          color: var(--ink-muted);
          border: 1px solid var(--border-strong);
        }
        .btn--ghost:hover:not(:disabled) {
          color: var(--ink);
          border-color: var(--ink-muted);
          background: var(--bg-elev-2);
        }
        .btn--danger {
          background: transparent;
          color: var(--danger);
          border: 1px solid rgba(255, 93, 93, 0.4);
        }
        .btn__spinner {
          width: 12px;
          height: 12px;
          border-radius: 50%;
          border: 2px solid currentColor;
          border-top-color: transparent;
          animation: spin 0.8s linear infinite;
        }
        .btn--loading .btn__label {
          opacity: 0.7;
        }
      `}</style>
    </button>
  );
});
