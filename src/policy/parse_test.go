package policy

import (
	"strings"
	"testing"
)

const validYAML = `
version: "1.0"
policy_id: ubi_claim_v1
action: ubi_claim
anchor_required: true
min_supplementary_points: 0
max_credential_age_seconds: 31536000
max_anchor_method_age_seconds: 86400
require_fresh_anchor_proof: false
nullifier_required: true
nullifier_context_tag: ubi_2026_q2
`

const validJSON = `{
  "version": "1.0",
  "policy_id": "ubi_claim_v1",
  "action": "ubi_claim",
  "anchor_required": true,
  "min_supplementary_points": 0,
  "max_credential_age_seconds": 31536000,
  "max_anchor_method_age_seconds": 86400,
  "require_fresh_anchor_proof": false,
  "nullifier_required": true,
  "nullifier_context_tag": "ubi_2026_q2"
}`

func TestParseYAML(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, raw []byte)
	}{
		{
			name: "happy path",
			data: validYAML,
		},
		{
			name:      "empty doc",
			data:      "",
			wantErr:   true,
			errSubstr: "empty",
		},
		{
			name:      "malformed yaml",
			data:      "version: \"1.0\"\n  bad:indent:  : :\n",
			wantErr:   true,
			errSubstr: "yaml",
		},
		{
			name:      "wrong version",
			data:      "version: \"2.0\"\npolicy_id: x\naction: y\n",
			wantErr:   true,
			errSubstr: "unsupported version",
		},
		{
			name:      "missing policy_id",
			data:      "version: \"1.0\"\naction: y\n",
			wantErr:   true,
			errSubstr: "policy_id",
		},
		{
			name:      "missing action",
			data:      "version: \"1.0\"\npolicy_id: x\n",
			wantErr:   true,
			errSubstr: "action",
		},
		{
			name:      "nullifier required without tag",
			data:      "version: \"1.0\"\npolicy_id: x\naction: y\nnullifier_required: true\n",
			wantErr:   true,
			errSubstr: "nullifier_context_tag",
		},
		{
			name:      "negative supplementary points",
			data:      "version: \"1.0\"\npolicy_id: x\naction: y\nmin_supplementary_points: -1\n",
			wantErr:   true,
			errSubstr: "min_supplementary_points",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseYAML([]byte(tt.data))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (policy=%+v)", tt.errSubstr, p)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.PolicyID != "ubi_claim_v1" {
				t.Fatalf("PolicyID = %q, want ubi_claim_v1", p.PolicyID)
			}
			if !p.AnchorRequired {
				t.Fatal("AnchorRequired should be true")
			}
			if p.NullifierContextTag != "ubi_2026_q2" {
				t.Fatalf("NullifierContextTag = %q, want ubi_2026_q2", p.NullifierContextTag)
			}
		})
	}
}

func TestParseJSON(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "happy path",
			data: validJSON,
		},
		{
			name:      "empty doc",
			data:      "",
			wantErr:   true,
			errSubstr: "empty",
		},
		{
			name:      "malformed json",
			data:      `{"version": "1.0",`,
			wantErr:   true,
			errSubstr: "json",
		},
		{
			name:      "wrong version",
			data:      `{"version":"0.9","policy_id":"x","action":"y"}`,
			wantErr:   true,
			errSubstr: "unsupported version",
		},
		{
			name:      "nullifier required without tag",
			data:      `{"version":"1.0","policy_id":"x","action":"y","nullifier_required":true}`,
			wantErr:   true,
			errSubstr: "nullifier_context_tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseJSON([]byte(tt.data))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (policy=%+v)", tt.errSubstr, p)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Action != "ubi_claim" {
				t.Fatalf("Action = %q, want ubi_claim", p.Action)
			}
		})
	}
}

func TestParseYAMLAndJSONEquivalence(t *testing.T) {
	py, err := ParseYAML([]byte(validYAML))
	if err != nil {
		t.Fatalf("yaml parse: %v", err)
	}
	pj, err := ParseJSON([]byte(validJSON))
	if err != nil {
		t.Fatalf("json parse: %v", err)
	}
	if py.PolicyID != pj.PolicyID ||
		py.Action != pj.Action ||
		py.AnchorRequired != pj.AnchorRequired ||
		py.MaxCredentialAgeSeconds != pj.MaxCredentialAgeSeconds ||
		py.MaxAnchorMethodAgeSeconds != pj.MaxAnchorMethodAgeSeconds ||
		py.NullifierRequired != pj.NullifierRequired ||
		py.NullifierContextTag != pj.NullifierContextTag {
		t.Fatalf("yaml and json parses diverged:\nyaml=%+v\njson=%+v", py, pj)
	}
}
