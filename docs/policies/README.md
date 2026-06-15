# Sample policies

Ready-to-use Personhood Policy DSL documents integrators can adopt or adapt.
Load them with the SDK (`personhood.ParsePolicyYAML` in Go, `verify(...)` in TS).

| File | Purpose |
|---|---|
| `default-floor.yaml` | Baseline check: requires an anchor **and** the near-free "floor" supplementary signals (`app-attest-device` + `ip-asn-reputation` + `captcha-turnstile` = 32 points). A sensible default for most integrators. |

The floor methods are registered by the reference server (`src/server`) when their
env vars are present; see `.example.env` and each method's README under
`src/methods/`. The floor never substitutes for an anchor — it raises the cost of
bulk fake signups while the anchor provides the one-human guarantee.
