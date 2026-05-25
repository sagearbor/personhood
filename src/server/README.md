# src/server

Reference REST API for the Personhood issuer. Hosts enrollment ceremonies, validates method completion, issues credentials. Stateless where possible; persists only method-completion records and signed credential metadata (NOT raw biometric data — that lives only on the user's device).

## Endpoint sketch (v0.1)

- `POST /enrollment/start` — create a session
- `POST /methods/{methodId}/begin` — start a ceremony for a specific method
- `POST /methods/{methodId}/complete` — submit ceremony response
- `POST /credentials/issue` — once required methods are complete, issue the W3C VC
- `GET /status-list/{listId}` — public revocation status list (W3C Status List 2021)
- `GET /.well-known/did.json` — issuer DID document (`did:web`)
