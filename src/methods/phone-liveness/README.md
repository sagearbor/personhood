# src/methods/phone-liveness

**Anchor method** (target strength 70–85).

Phone-camera liveness + device attestation. Combines:

- **Liveness check** — Apple FaceID / Android BiometricPrompt native first; hosted SDK (FaceTec / iProov / Sumsub) fallback for older devices.
- **Device attestation** — Apple App Attest / Google Play Integrity API. Confirms request originated from a genuine, unmodified app on a real device.

The server validates the attestation token from Apple/Google AND the liveness assertion from the chosen SDK. Failure of either rejects the ceremony.

## Known weaknesses

- Rooted / jailbroken devices weaken attestation
- Sophisticated 3D-printed masks can defeat naive liveness — recommend SDKs with active-challenge (blink, head turn)
- Server-side attestation receipt verification has a small latency cost

## Pricing notes

Native Apple/Android: free. Hosted SDKs typically $0.10–$0.30 per verification.
