'use client';

import { Button } from './Button';
import { Card } from './Card';
import { Field } from './Field';

/**
 * Shown in place of the boot spinner when GET /v1/config reports
 * invite_code_required: true, before any session exists — the session must
 * be created with the code (see app/page.tsx's beginSession). The field is
 * prefilled from localStorage (lib/inviteCode.ts) so a friend reusing this
 * device after "Start over" only has to tap Continue, not retype the code.
 */
export function InviteGate({
  value,
  onChange,
  error,
  submitting,
  onSubmit,
}: {
  value: string;
  onChange: (value: string) => void;
  error: string | null;
  submitting: boolean;
  onSubmit: () => void;
}) {
  return (
    <Card
      title="Invite code required"
      subtitle="This deployment is invite-only right now. Enter the code you were given to begin."
      status={error ? 'error' : 'idle'}
      statusLabel={error ? 'invalid code' : 'awaiting code'}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim() && !submitting) onSubmit();
        }}
      >
        <Field
          label="invite code"
          placeholder="e.g. FRIENDS2026"
          autoComplete="off"
          autoCapitalize="characters"
          spellCheck={false}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          invalid={!!error}
          hint={error || 'Remembered on this device, so "Start over" won’t make you retype it.'}
        />
        <div className="row">
          <Button type="submit" loading={submitting} disabled={!value.trim()}>
            Continue &rarr;
          </Button>
        </div>
      </form>
      <style jsx>{`
        .row {
          display: flex;
          gap: var(--s-3);
          margin-top: var(--s-4);
        }
      `}</style>
    </Card>
  );
}
