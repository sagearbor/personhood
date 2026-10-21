// Helpers for getting the issued credential off the issuer page and onto
// the holder's phone: download as a .json file, or hand it to the OS share
// sheet (as a file where supported, else as text).
//
// Pure apart from saveCredentialFile(), which touches the DOM — see
// lib/credentialFile.test.ts.

export const CREDENTIAL_FILENAME = 'personhood-credential.json';
export const CREDENTIAL_MIME = 'application/json';

/** The exact bytes we save/share/copy: pretty-printed JSON. */
export function credentialJSON(credential: unknown): string {
  return JSON.stringify(credential, null, 2);
}

/** Minimal slice of Navigator we depend on, so this is testable in node. */
export type ShareNavigator = {
  share?: (data: ShareData) => Promise<void>;
  canShare?: (data: ShareData) => boolean;
};

export type ShareMode = 'files' | 'text' | 'none';

/**
 * How to share on this browser: as a File when the Web Share API accepts
 * files (Android Chrome, iOS Safari 15+), as plain text when it only shares
 * text, or not at all (most desktop browsers — the Share button is hidden).
 */
export function pickShareMode(nav: ShareNavigator | undefined, file: File | null): ShareMode {
  if (!nav || typeof nav.share !== 'function') return 'none';
  if (file && typeof nav.canShare === 'function') {
    try {
      if (nav.canShare({ files: [file] })) return 'files';
    } catch {
      // some browsers throw on unsupported keys; fall through to text
    }
  }
  return 'text';
}

/** Triggers a browser download of the credential as personhood-credential.json. */
export function saveCredentialFile(credential: unknown): void {
  const blob = new Blob([credentialJSON(credential)], { type: CREDENTIAL_MIME });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = CREDENTIAL_FILENAME;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Give the download a moment to start before revoking (Safari needs it).
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
