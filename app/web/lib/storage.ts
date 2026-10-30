// IndexedDB wrapper for the Personhood enrollment session + the issued
// credential. v0.1 stores the W3C VC in plaintext (the credential itself is
// not a secret — anyone in possession of it can present it; what matters is
// the holder's private key, which will be wrapped behind WebAuthn in v0.2).
//
// We also persist the in-flight session ID so a Persona redirect-and-return
// can resume the ceremony rather than starting over.

import type { Credential } from './api';

const DB_NAME = 'personhood-v1';
const DB_VERSION = 1;
const STORE_CRED = 'credentials';
const STORE_KV = 'kv';

type Stored = {
  id: string;
  credential: Credential;
  savedAt: string;
};

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_CRED)) {
        db.createObjectStore(STORE_CRED, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_KV)) {
        db.createObjectStore(STORE_KV);
      }
    };
    req.onsuccess = () => resolve(req.result);
  });
}

export async function saveCredential(credential: Credential): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_CRED, 'readwrite');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    const entry: Stored = {
      id: credential.id,
      credential,
      savedAt: new Date().toISOString(),
    };
    tx.objectStore(STORE_CRED).put(entry);
  });
  db.close();
}

export async function listCredentials(): Promise<Stored[]> {
  const db = await openDB();
  const out: Stored[] = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_CRED, 'readonly');
    const req = tx.objectStore(STORE_CRED).getAll();
    req.onsuccess = () => resolve(req.result as Stored[]);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return out;
}

export async function deleteCredential(id: string): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_CRED, 'readwrite');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.objectStore(STORE_CRED).delete(id);
  });
  db.close();
}

// --- session checkpoint key/value (for Persona redirect-and-return) -----

const KEY_SESSION = 'session_v1';

type SessionCheckpoint = {
  sessionId: string;
  holderDid: string;
  issuerDid: string;
  expiresAt: string;
  step: 'email' | 'sms' | 'id' | 'credential';
  emailSent?: string;
  smsSent?: string;
};

export async function saveSession(c: SessionCheckpoint): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_KV, 'readwrite');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.objectStore(STORE_KV).put(c, KEY_SESSION);
  });
  db.close();
}

export async function loadSession(): Promise<SessionCheckpoint | null> {
  const db = await openDB();
  const v: SessionCheckpoint | undefined = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KV, 'readonly');
    const req = tx.objectStore(STORE_KV).get(KEY_SESSION);
    req.onsuccess = () => resolve(req.result as SessionCheckpoint | undefined);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return v ?? null;
}

export async function clearSession(): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_KV, 'readwrite');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.objectStore(STORE_KV).delete(KEY_SESSION);
  });
  db.close();
}

// --- holder Ed25519 keypair (see lib/holderkey.ts) -----------------------
//
// Stored as { publicKeyB64, privateKey: CryptoKey } with a non-extractable
// private key; IndexedDB's structured clone keeps the CryptoKey opaque.
// Earlier versions stored { publicKeyB64, privateKeyB64 } (base64 pkcs8);
// holderkey.ts migrates that shape on first load and overwrites it here.

const KEY_HOLDER_KEY = 'holder_key_v1';

type StoredHolderKeyPair =
  | { publicKeyB64: string; privateKey: CryptoKey }
  | { publicKeyB64: string; privateKeyB64: string };

export async function saveHolderKeyPair(pair: StoredHolderKeyPair): Promise<void> {
  await kvPut(KEY_HOLDER_KEY, pair);
}

export async function loadHolderKeyPair(): Promise<StoredHolderKeyPair | null> {
  return (await kvGet<StoredHolderKeyPair>(KEY_HOLDER_KEY)) ?? null;
}

// --- device passkey id (see lib/webauthn.ts) ------------------------------
//
// The credential id of the passkey registered at the save step. Once set,
// holderkey.ts asks for that passkey's biometric / PIN check before signing.

const KEY_DEVICE_PASSKEY = 'device_passkey_id_v1';

export async function saveDevicePasskeyId(id: string): Promise<void> {
  await kvPut(KEY_DEVICE_PASSKEY, id);
}

export async function loadDevicePasskeyId(): Promise<string | null> {
  return (await kvGet<string>(KEY_DEVICE_PASSKEY)) ?? null;
}

async function kvPut(key: string, value: unknown): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_KV, 'readwrite');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.objectStore(STORE_KV).put(value, key);
  });
  db.close();
}

async function kvGet<T>(key: string): Promise<T | undefined> {
  const db = await openDB();
  const v: T | undefined = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KV, 'readonly');
    const req = tx.objectStore(STORE_KV).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return v;
}
