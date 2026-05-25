# src/credential

W3C Verifiable Credential issuer and verifier for `PersonhoodCredential`. Signs credentials with the issuer's Ed25519 key (`did:web` issuer DID). Verifies presented credentials: signature, status list, expiry, integrity of `verifiedMethods` array.

Holders are `did:key`. Selective disclosure deferred to v0.2 (would require BBS+ signatures).
