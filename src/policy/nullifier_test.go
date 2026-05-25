package policy

import (
	"strings"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

func validBinding() types.NullifierBinding {
	return types.NullifierBinding{
		Commitment: "deadbeefcafebabe",
		Curve:      "bn254",
		Scheme:     "pedersen-v1",
	}
}

func TestDeriveNullifier(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		a, err := DeriveNullifier(validBinding(), "ubi_2026_q2")
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		b, err := DeriveNullifier(validBinding(), "ubi_2026_q2")
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		if a != b {
			t.Fatalf("non-deterministic: %s != %s", a, b)
		}
		// sha256 hex is 64 chars
		if len(a) != 64 {
			t.Fatalf("expected 64-char hex, got %d (%s)", len(a), a)
		}
	})

	t.Run("different tags produce different nullifiers", func(t *testing.T) {
		a, _ := DeriveNullifier(validBinding(), "ubi_2026_q2")
		b, _ := DeriveNullifier(validBinding(), "ubi_2026_q3")
		if a == b {
			t.Fatalf("different tags produced same nullifier: %s", a)
		}
	})

	t.Run("different commitments produce different nullifiers", func(t *testing.T) {
		bind1 := validBinding()
		bind2 := validBinding()
		bind2.Commitment = "c0ffeec0ffee"
		a, _ := DeriveNullifier(bind1, "vote/2026")
		b, _ := DeriveNullifier(bind2, "vote/2026")
		if a == b {
			t.Fatalf("different commitments produced same nullifier: %s", a)
		}
	})

	errCases := []struct {
		name    string
		binding types.NullifierBinding
		tag     string
		want    string
	}{
		{"empty commitment", types.NullifierBinding{Curve: "bn254", Scheme: "pedersen-v1"}, "tag", "commitment"},
		{"empty scheme", types.NullifierBinding{Commitment: "ab", Curve: "bn254"}, "tag", "scheme"},
		{"empty curve", types.NullifierBinding{Commitment: "ab", Scheme: "pedersen-v1"}, "tag", "curve"},
		{"empty tag", validBinding(), "", "context tag"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveNullifier(tc.binding, tc.tag)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
