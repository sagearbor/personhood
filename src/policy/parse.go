// Package policy implements the Personhood Policy DSL parser and evaluator.
//
// Integrators declare verification requirements in a small declarative
// document (YAML or JSON). The parser unmarshals the document into the
// canonical types.Policy and runs structural validation; the evaluator
// (see evaluate.go) checks a presented credential against the policy and
// returns a structured types.EvaluationResult.
//
// Both encodings — YAML and JSON — produce identical results because the
// canonical types.Policy struct carries both `json:` and `yaml:` struct tags.
package policy

import (
	"encoding/json"
	"fmt"

	"github.com/sagearbor/personhood/pkg/types"
	"gopkg.in/yaml.v3"
)

// ParseYAML unmarshals a YAML-encoded Personhood policy document into a
// types.Policy and validates it. Returns an error if the YAML is malformed
// or if the resulting policy fails types.Policy.Validate().
func ParseYAML(data []byte) (types.Policy, error) {
	var p types.Policy
	if len(data) == 0 {
		return p, fmt.Errorf("policy: empty YAML document")
	}
	if err := yaml.Unmarshal(data, &p); err != nil {
		return types.Policy{}, fmt.Errorf("policy: yaml unmarshal: %w", err)
	}
	if err := p.Validate(); err != nil {
		return types.Policy{}, err
	}
	return p, nil
}

// ParseJSON unmarshals a JSON-encoded Personhood policy document into a
// types.Policy and validates it. Returns an error if the JSON is malformed
// or if the resulting policy fails types.Policy.Validate().
func ParseJSON(data []byte) (types.Policy, error) {
	var p types.Policy
	if len(data) == 0 {
		return p, fmt.Errorf("policy: empty JSON document")
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return types.Policy{}, fmt.Errorf("policy: json unmarshal: %w", err)
	}
	if err := p.Validate(); err != nil {
		return types.Policy{}, err
	}
	return p, nil
}
