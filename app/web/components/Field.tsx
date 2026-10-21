'use client';

import { type InputHTMLAttributes, forwardRef, useId } from 'react';

type FieldProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
  invalid?: boolean;
};

export const Field = forwardRef<HTMLInputElement, FieldProps>(function Field(
  { label, hint, invalid, id, ...props },
  ref,
) {
  // useId (not Math.random) so the id is stable across the static-export
  // prerender and hydration — a mismatched id would break the label link.
  const autoId = useId();
  const fieldId = id ?? props.name ?? `field-${autoId}`;
  const hintId = `${fieldId}-hint`;
  return (
    <div className="field" data-invalid={invalid || undefined}>
      <label className="field__label" htmlFor={fieldId}>
        {label}
      </label>
      <input
        ref={ref}
        id={fieldId}
        aria-invalid={invalid || undefined}
        aria-describedby={hint ? hintId : undefined}
        {...props}
        className="field__input"
      />
      {hint ? (
        <span className="field__hint" id={hintId}>
          {hint}
        </span>
      ) : null}
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
    </div>
  );
});
