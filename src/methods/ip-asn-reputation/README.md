# ip-asn-reputation

**Supplementary** verification method. A near-free anti-bot floor that scores the
client's IP / ASN to catch datacenter, VPN, proxy, and Tor signups.
"Near-free mandatory floor" per `docs/06-methods-catalog.md`.

| Property | Value |
|---|---|
| Type | supplementary |
| Strength | 10 |
| Cost | ~$0.001 / lookup |
| Friction | low |
| Freshness | 7 days |
| Airdrop test | ⚠️ (mobile/satellite IPs sometimes flagged) |

It catches **>90% of naive bot signups** but is cheaply defeated by residential
proxies and rotating mobile IPs, so it never substitutes for an anchor — the
policy DSL enforces this independently.

## Flow

The check is entirely **server-side**; the client does nothing.

1. **BeginCeremony** → returns an informational `ChallengeData` (type `ip-asn`,
   `{"note": "server-evaluated; client action not required"}`). `SessionID` is
   required.
2. The server resolves the real client IP (from `X-Forwarded-For` /
   `RemoteAddr`) and passes it in **CompleteCeremony** via
   `ResponseData.Payload["ip"]`.
3. **CompleteCeremony** looks the IP up via the configured `ReputationProvider`
   and applies the disqualifiers. Success records a SHA-256 attestation digest
   over `session_id || ip || asn`; the raw IP never lands on the credential.

> The server is responsible for passing the **real** client IP. Behind a proxy /
> load balancer, parse the left-most untrusted hop of `X-Forwarded-For` (or use
> your platform's trusted-proxy resolution); a spoofable IP defeats this floor.

## Outcomes

| Condition | `CompleteCeremony` |
|---|---|
| missing `ip` payload | `Success=false`, `missing_ip` |
| datacenter IP (default reject) | `Success=false`, `ip_datacenter` |
| proxy IP (default reject) | `Success=false`, `ip_proxy` |
| Tor exit (default reject) | `Success=false`, `ip_tor` |
| VPN IP, `RejectVPN=true` | `Success=false`, `ip_vpn` |
| clean / VPN-by-default | `Success=true` + attestation digest |
| provider lookup error | non-nil `error` (unattributable; not a user failure) |

## Providers

`ReputationProvider` is the extension point:

```go
type Reputation struct {
    ASN          int
    Org          string
    IsDatacenter bool
    IsVPN        bool
    IsProxy      bool
    IsTor        bool
}

type ReputationProvider interface {
    Lookup(ctx context.Context, ip string) (Reputation, error)
}
```

- **`StaticProvider`** (shipped) — in-memory `map[string]Reputation`, ideal for
  tests and allowlists/denylists. Unknown IPs resolve to the clean zero value
  (override via `Fallback`).
- **Production** — wire **MaxMind GeoIP2 Anonymous-IP** or **IPQualityScore**
  behind `ReputationProvider`. Both expose datacenter/VPN/proxy/Tor flags and an
  ASN that map directly onto `Reputation`.

## Configuration

```go
m := ipasnreputation.NewMethod(ipasnreputation.DefaultConfig(provider))
```

`DefaultConfig` rejects datacenter, proxy, and Tor but **allows VPNs** — VPNs are
common for privacy-conscious legitimate users. Because Go booleans can't
distinguish "unset" from `false`, start from `DefaultConfig` and flip individual
`Reject*` flags rather than building a bare `Config`:

```go
cfg := ipasnreputation.DefaultConfig(provider)
cfg.RejectVPN = true // stricter posture
m := ipasnreputation.NewMethod(cfg)
```

`NewMethod` panics if `Config.Provider` is nil.
