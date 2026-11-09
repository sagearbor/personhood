package fuzzyextractorselfie

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// TestEvalTemplates measures false match and false non-match rates of the
// real Gen/Rep on templates made from real face photos. It is skipped
// unless SELFIE_EVAL_TEMPLATES points at a JSON file of
// [{"person": "...", "template_b64": "..."}], as written by
// scripts/selfie-eval (docs/selfie-anchor.md). Run with -v to see the
// numbers; it only fails on malformed input.
//
//	SELFIE_EVAL_TEMPLATES=tmp/selfie-eval/templates.json go test -v -run TestEvalTemplates .
func TestEvalTemplates(t *testing.T) {
	path := os.Getenv("SELFIE_EVAL_TEMPLATES")
	if path == "" {
		t.Skip("SELFIE_EVAL_TEMPLATES not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var items []struct {
		Person      string `json:"person"`
		TemplateB64 string `json:"template_b64"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	type sample struct {
		person   string
		template []byte
	}
	samples := make([]sample, 0, len(items))
	for _, it := range items {
		b, err := base64.StdEncoding.DecodeString(it.TemplateB64)
		if err != nil || len(b) != TemplateBytes {
			t.Fatalf("bad template for %s", it.Person)
		}
		samples = append(samples, sample{it.Person, b})
	}

	// Pairwise: enroll a (Gen), present b (Rep); a match recovers a's commitment.
	var gen, genMiss, imp, impHit int
	for i := range samples {
		helper, commitment, err := Gen(samples[i].template)
		if err != nil {
			t.Fatal(err)
		}
		for j := range samples {
			if i == j {
				continue
			}
			c, ok, err := Rep(samples[j].template, helper)
			if err != nil {
				t.Fatal(err)
			}
			match := ok && c == commitment
			if samples[i].person == samples[j].person {
				gen++
				if !match {
					genMiss++
				}
			} else {
				imp++
				if match {
					impHit++
				}
			}
		}
	}
	t.Logf("pairs: genuine %d, false non-match %d (FNMR %.3f); impostor %d, false match %d (FMR %.5f)",
		gen, genMiss, rate(genMiss, gen), imp, impHit, rate(impHit, imp))

	// Enrollment simulation: everyone enrolls their first sample in turn
	// (in person order); count honest people refused as duplicates. Then
	// everyone tries again with their other samples; count second
	// identities that get through.
	byPerson := map[string][]([]byte){}
	var order []string
	for _, s := range samples {
		if _, ok := byPerson[s.person]; !ok {
			order = append(order, s.person)
		}
		byPerson[s.person] = append(byPerson[s.person], s.template)
	}
	sort.Strings(order)
	m := NewMethod(Config{Accumulator: NewInMemoryAccumulator()})
	ctx := context.Background()
	refused := 0
	for _, p := range order {
		if !enrollForEval(t, m, ctx, byPerson[p][0]) {
			refused++
		}
	}
	retries, sybils := 0, 0
	for _, p := range order {
		for _, tpl := range byPerson[p][1:] {
			retries++
			if enrollForEval(t, m, ctx, tpl) {
				sybils++
			}
		}
	}
	t.Logf("enrollment: %d people, %d honest first enrollments refused as duplicates; %d second attempts, %d got a second identity",
		len(order), refused, retries, sybils)
}

func enrollForEval(t *testing.T, m *Method, ctx context.Context, tpl []byte) bool {
	t.Helper()
	_, found, err := m.accumulator.FindDuplicate(ctx, tpl)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		return false
	}
	helper, commitment, err := Gen(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.accumulator.Add(ctx, EnrollmentRecord{Helper: helper, Commitment: commitment}); err != nil {
		t.Fatal(err)
	}
	return true
}

func rate(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
