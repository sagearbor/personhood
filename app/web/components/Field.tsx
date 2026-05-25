'use client';

import { type InputHTMLAttributes, forwardRef } from 'react';

type FieldProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
  invalid?: boolean;
};

export const Field = forwardRef<HTMLInputElement, FieldProps>(function Field(
  { label, hint, invalid, id, ...props },
  ref,
) {
  const fieldId = id ?? props.name ?? Math.random().toString(36).slice(2);
  return (
    <label className="field" htmlFor={fieldId} data-invalid={invalid || undefined}>
      <span className="field__label">{label}</span>
      <input ref={ref} id={fieldId} {...props} className="field__input" />
      {hint ? <span className="field__hint">{hint}</span> : null}
      <style jsx>{`
        .field {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .field__label {
          font-family: var(--f-mono);
          font-size: 11px;
          letter-spacing: 0.12em;
          text-transform: uppercase;
          color: var(--ink-muted);
        }
        .field__input {
          padding: 14px 14px;
          background: var(--bg);
          border: 1px solid var(--border-strong);
          border-radius: var(--r-2);
          color: var(--ink);
          font-size: 16px;
          /* font-size 16+ prevents iOS Safari from zooming on focus */
          transition: border-color var(--t-fast) var(--ease-out), box-shadow var(--t-fast) var(--ease-out);
          width: 100%;
        }
        .field__input:focus {
          border-color: var(--accent);
          box-shadow: 0 0 0 4px var(--accent-dim);
        }
        .field__input::placeholder {
          color: var(--ink-faint);
        }
        .field__hint {
          font-size: 12px;
          color: var(--ink-faint);
        }
        .field[data-invalid] .field__input {
          border-color: var(--danger);
        }
        .field[data-invalid] .field__hint {
          color: var(--danger);
        }
      `}</style>
    </label>
  );
});
