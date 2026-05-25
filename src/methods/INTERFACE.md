# Method Plugin Interface

Each verification method (phone-liveness, email, sms, future methods) is a standalone Go module under `src/methods/<name>/` that implements the `Method` interface.

## Go interface (target)

```go
type Method interface {
    // Metadata
    ID() string                      // unique, e.g. "phone-liveness"
    Type() MethodType                // anchor | supplementary
    Strength() int                   // 0–100; anchors must be ≥50, supplementary <50
    Cost() decimal.Decimal           // $ per verification (0 for free)
    UXFriction() FrictionLevel       // low | med | high
    PlatformRequirements() []string  // e.g. ["mobile", "biometric_capable_device"]
    FreshnessLifetime() time.Duration

    // Lifecycle
    IsAvailableForUser(ctx UserContext) (bool, string) // bool + reason if unavailable
    BeginCeremony(ctx CeremonyContext) (ChallengeData, error)
    CompleteCeremony(ctx CeremonyContext, response ResponseData) (MethodResult, error)

    // Health
    HealthCheck(ctx context.Context) error
    Version() string
}
```

## TypeScript interface (target)

The TypeScript SDK declares the same contract for client-side ceremony helpers and for any TS-implemented methods. See `sdk/typescript/`.

## Registration

Each method package registers itself in its `init()` (or via explicit wire-up by the server). See `../registry/INTERFACE.md`.

## v0.1 methods

- `phone-liveness/` — ANCHOR (target strength 70–85)
- `email/` — supplementary (target strength 5–10)
- `sms/` — supplementary (target strength 10–15)

## Future methods (v0.2+)

Fuzzy extractor (anchor), Plaid bank link (anchor), Persona/Onfido KYC (anchor), iris/orb (anchor), web of trust (supplementary), government ID + liveness (anchor).
