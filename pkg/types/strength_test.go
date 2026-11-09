package types

import "testing"

func TestEffectiveStrength(t *testing.T) {
	md := MethodMetadata{ID: "document-chip-zk", Strength: 80}
	cases := []struct {
		result, want int
	}{
		{0, 80},  // not set: the metadata strength
		{70, 70}, // weaker evidence (no Active Authentication)
		{95, 80}, // a result can never raise the strength
		{-1, 80},
	}
	for _, c := range cases {
		if got := EffectiveStrength(md, MethodResult{Strength: c.result}); got != c.want {
			t.Errorf("result strength %d: got %d, want %d", c.result, got, c.want)
		}
	}
}
