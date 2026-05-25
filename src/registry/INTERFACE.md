# Registry Interface

The registry is a runtime catalog of verification methods.

## Operations

- `RegisterMethod(m Method)` — called by each method package's `init()` or by explicit wire-up
- `GetMethod(id string) (Method, bool)` — lookup by `methodId` (e.g. `"phone-liveness"`)
- `ListMethods() []Method` — return all registered methods
- `ListByType(t MethodType) []Method` — filter to `anchor` or `supplementary`

## Invariants

- Method IDs are unique strings, registered exactly once per process
- A method's metadata (strength, cost, friction) is immutable for the lifetime of the process
- Anchor methods must declare `strength >= 50`; supplementary methods must declare `strength < 50` — registration fails if violated

See the Method plugin interface in `../methods/INTERFACE.md`.
