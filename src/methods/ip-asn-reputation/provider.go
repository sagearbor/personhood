package ipasnreputation

import "context"

// Reputation is the per-IP reputation signal a ReputationProvider returns. The
// zero value is "clean": an unknown IP with no datacenter/VPN/proxy/Tor flags
// passes every default disqualifier.
type Reputation struct {
	// ASN is the autonomous system number the IP belongs to (0 if unknown).
	ASN int

	// Org is the human-readable owner of the ASN (e.g. "Amazon.com, Inc."),
	// for logging/audit only.
	Org string

	// IsDatacenter reports that the IP belongs to a hosting / cloud range
	// (AWS, GCP, OVH, …) rather than a residential / mobile ISP.
	IsDatacenter bool

	// IsVPN reports that the IP is a known commercial VPN exit.
	IsVPN bool

	// IsProxy reports that the IP is an open / anonymizing proxy.
	IsProxy bool

	// IsTor reports that the IP is a Tor exit node.
	IsTor bool
}

// ReputationProvider resolves an IP address to a Reputation. Production
// deployments wire a real provider (MaxMind GeoIP2 Anonymous-IP, IPQualityScore,
// etc.) behind this interface; tests and small deployments can use
// StaticProvider.
//
// Lookup must be safe for concurrent use.
type ReputationProvider interface {
	// Lookup resolves ip to a Reputation. An error means the lookup itself
	// failed (provider unreachable, quota, malformed input); the method treats
	// that as unattributable and surfaces the error rather than failing the
	// user.
	Lookup(ctx context.Context, ip string) (Reputation, error)
}

// StaticProvider is an in-memory ReputationProvider backed by a fixed map. It
// is useful for tests, allowlists/denylists, and air-gapped deployments. Any IP
// absent from the map resolves to Fallback (defaulting to the clean zero value).
//
// StaticProvider is read-only after construction and therefore safe for
// concurrent use.
type StaticProvider struct {
	entries  map[string]Reputation
	Fallback Reputation
}

var _ ReputationProvider = (*StaticProvider)(nil)

// NewStaticProvider builds a StaticProvider from the given map. A nil map is
// allowed (every IP then resolves to the clean zero-value Fallback). The map is
// copied so later mutations by the caller do not affect lookups.
func NewStaticProvider(entries map[string]Reputation) *StaticProvider {
	cp := make(map[string]Reputation, len(entries))
	for k, v := range entries {
		cp[k] = v
	}
	return &StaticProvider{entries: cp}
}

// Lookup implements ReputationProvider. Unknown IPs resolve to Fallback.
func (p *StaticProvider) Lookup(_ context.Context, ip string) (Reputation, error) {
	if r, ok := p.entries[ip]; ok {
		return r, nil
	}
	return p.Fallback, nil
}
