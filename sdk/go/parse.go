package personhood

import (
	"encoding/json"
	"fmt"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/policy"
)

// ParsePolicyYAML parses and validates a Personhood policy document encoded as
// YAML. It is a re-export of the policy package so integrators depend only on
// this SDK module.
func ParsePolicyYAML(data []byte) (types.Policy, error) {
	return policy.ParseYAML(data)
}

// ParsePolicyJSON parses and validates a Personhood policy document encoded as
// JSON.
func ParsePolicyJSON(data []byte) (types.Policy, error) {
	return policy.ParseJSON(data)
}

// ParseCredential unmarshals a JSON-encoded PersonhoodCredential (a presented
// W3C VC) into the canonical struct. It runs structural validation so callers
// get an early, clear error on malformed input; full signature verification
// still happens in Verify.
func ParseCredential(data []byte) (types.PersonhoodCredential, error) {
	if len(data) == 0 {
		return types.PersonhoodCredential{}, fmt.Errorf("personhood: empty credential document")
	}
	var cred types.PersonhoodCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return types.PersonhoodCredential{}, fmt.Errorf("personhood: parse credential: %w", err)
	}
	if err := cred.Validate(); err != nil {
		return types.PersonhoodCredential{}, fmt.Errorf("personhood: invalid credential: %w", err)
	}
	return cred, nil
}
