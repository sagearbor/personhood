'use client';

import { useState } from 'react';
import { Button } from '../Button';
import { Card } from '../Card';
import type { Status } from '../StatusPill';
import { issueCredential, type StartEnrollmentResponse, type Credential } from '@/lib/api';
import { saveCredential, clearSession } from '@/lib/storage';
import { registerDevicePasskey, isWebAuthnAvailable } from '@/lib/webauthn';

export function CredentialStep({
  session,
  credential,
  hasAnchor,
  onIssued,
  onRestart,
}: {
  session: StartEnrollmentResponse;
  credential: Credential | null;
  hasAnchor: boolean;
  onIssued: (c: Credential) => void;
  onRestart: () => void;
}) {
  const [status, setStatus] = useState<Status>(credential ? 'ok' : 'idle');
  const [statusText, setStatusText] = useState<string>(credential ? 'issued' : 'ready to issue');
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  async function issue() {
    setErr(null);
    setStatus('pending');
    setStatusText('signing credential');
    try {
      const { credential: cred } = await issueCredential(session.session_id);
      setStatus('ok');
      setStatusText('issued');
      onIssued(cred);
    } catch (e) {
      setStatus('error');
      setStatusText('issue failed');
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function save() {
    if (!credential) return;
    setErr(null);
    try {
      if (isWebAuthnAvailable()) {
        // Optional biometric registration to demo the wallet UX. Failure to
        // register (e.g. user cancels) is non-fatal — the credential still saves.
        await registerDevicePasskey().catch(() => null);
      }
      await saveCredential(credential);
      setSaved(true);
      await clearSession().catch(() => {});
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function copyJSON() {
    if (!credential) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(credential, null, 2));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'clipboard not available');
    }
  }

  return (
    <Card
      title={credential ? 'Your Personhood credential' : 'Issue your credential'}
      subtitle={
        credential
          ? hasAnchor
            ? 'Signed W3C Verifiable Credential, bound to your device DID. Save it locally to reuse it anywhere.'
            : 'Signed W3C Verifiable Credential. No anchor was completed, so this credential will fail policies requiring “anchor_required”.'
          : 'The issuer signs everything you have verified so far into one W3C VC. The credential is yours — the server keeps a digest, never the raw data.'
      }
      status={status}
      statusLabel={statusText}
      footer={
        <span>
          Issuer <code className="break">{session.issuer_did}</code>
        </span>
      }
    >
      {!credential && (
        <div className="row">
          <Button onClick={issue} loading={status === 'pending'}>
            Sign &amp; issue
          </Button>
        </div>
      )}

      {credential && (
        <>
          <div className="meta">
            <dl>
              <dt>Holder DID</dt>
              <dd className="break">{credential.credentialSubject.id}</dd>
              <dt>Anchor</dt>
              <dd>
                {credential.credentialSubject.anchorMethodId ? (
                  <code>{credential.credentialSubject.anchorMethodId}</code>
                ) : (
                  <span className="warn">none (this credential is supplementary-only)</span>
                )}
              </dd>
              <dt>Verified methods</dt>
              <dd>
                {credential.credentialSubject.verifiedMethods.map((m) => (
                  <span key={m.method_id} className="chip">
                    {m.method_id} · {m.strength}
                  </span>
                ))}
              </dd>
              <dt>Expires</dt>
              <dd>{new Date(credential.expirationDate).toLocaleDateString()}</dd>
            </dl>
          </div>

          <div className="row">
            <Button onClick={save} disabled={saved}>
              {saved ? 'Saved to this device ✓' : 'Save to this device'}
            </Button>
            <Button variant="ghost" onClick={copyJSON}>
              {copied ? 'Copied!' : 'Copy JSON'}
            </Button>
            <Button variant="ghost" onClick={onRestart}>
              Start over
            </Button>
          </div>

          <details className="json">
            <summary>Show full credential JSON</summary>
            <pre>{JSON.stringify(credential, null, 2)}</pre>
          </details>
        </>
      )}

      {err && <p className="err">{err}</p>}

      <style jsx>{`
        .row {
          display: flex;
          gap: var(--s-3);
          flex-wrap: wrap;
        }
        .meta {
          background: var(--bg);
          border: 1px solid var(--border);
          border-radius: var(--r-2);
          padding: var(--s-3) var(--s-4);
        }
        dl {
          display: grid;
          grid-template-columns: 100px 1fr;
          gap: 8px 12px;
          margin: 0;
          font-size: 13px;
        }
        dt {
          font-family: var(--f-mono);
          font-size: 11px;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: var(--ink-faint);
          padding-top: 1px;
        }
        dd {
          margin: 0;
          color: var(--ink);
          word-break: break-all;
        }
        .break {
          word-break: break-all;
          font-family: var(--f-mono);
          font-size: 12px;
        }
        .chip {
          display: inline-block;
          font-family: var(--f-mono);
          font-size: 11px;
          padding: 3px 8px;
          margin: 0 6px 4px 0;
          border-radius: 999px;
          background: var(--accent-dim);
          color: var(--accent);
          border: 1px solid var(--border-accent);
        }
        .warn {
          color: var(--warning);
          font-style: italic;
        }
        .json {
          background: var(--bg);
          border: 1px solid var(--border);
          border-radius: var(--r-2);
          overflow: hidden;
        }
        .json summary {
          padding: 10px 14px;
          cursor: pointer;
          font-family: var(--f-mono);
          font-size: 12px;
          color: var(--ink-muted);
        }
        .json pre {
          margin: 0;
          padding: 14px;
          font-family: var(--f-mono);
          font-size: 11px;
          line-height: 1.5;
          color: var(--ink-muted);
          white-space: pre-wrap;
          word-break: break-all;
          max-height: 60vh;
          overflow: auto;
          border-top: 1px solid var(--border);
        }
        .err {
          margin: 0;
          color: var(--danger);
          font-size: 13px;
          font-family: var(--f-mono);
        }
      `}</style>
    </Card>
  );
}
