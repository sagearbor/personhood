package server

import (
	"net/http"
	"testing"

	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
	socialvouching "github.com/sagearbor/personhood/src/methods/social-vouching"
)

// TestBuildDependencies_FuzzyExtractorAndSocialVouching_OptInGating proves
// checklist #10a/#10b's registration is opt-in (unlike, say, ip-asn-
// reputation's always-on floor): a default BuildDependencies call must NOT
// advertise either method, matching every other non-round-1 method's
// "registration changes what a deployment advertises, so it needs an
// explicit signal" convention.
func TestBuildDependencies_FuzzyExtractorAndSocialVouching_OptInGating(t *testing.T) {
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatalf("BuildDependencies: %v", err)
	}
	if _, ok := deps.Registry.Get(fuzzyextractorselfie.MethodID); ok {
		t.Error("fuzzy-extractor-selfie registered without FUZZY_EXTRACTOR_ENABLED")
	}
	if _, ok := deps.Registry.Get(socialvouching.MethodID); ok {
		t.Error("social-vouching-graph registered without SOCIAL_VOUCHING_ENABLED")
	}
}

func TestBuildDependencies_FuzzyExtractorEnabled(t *testing.T) {
	t.Setenv("FUZZY_EXTRACTOR_ENABLED", "1")

	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatalf("BuildDependencies: %v", err)
	}
	m, ok := deps.Registry.Get(fuzzyextractorselfie.MethodID)
	if !ok {
		t.Fatal("fuzzy-extractor-selfie not registered with FUZZY_EXTRACTOR_ENABLED=1")
	}
	md := m.Metadata()
	if md.Strength < 50 {
		t.Errorf("fuzzy-extractor-selfie strength = %d, want an anchor-grade (>=50) strength", md.Strength)
	}
}

func TestBuildDependencies_SocialVouchingEnabled_RequiresSecret(t *testing.T) {
	t.Setenv("SOCIAL_VOUCHING_ENABLED", "1")
	t.Setenv("SOCIAL_VOUCHING_SECRET", "")

	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("BuildDependencies with SOCIAL_VOUCHING_ENABLED=1 but no secret: want error, got nil")
	}
}

func TestBuildDependencies_SocialVouchingEnabled_RegistersMethodAndVouchRoute(t *testing.T) {
	t.Setenv("SOCIAL_VOUCHING_ENABLED", "1")
	t.Setenv("SOCIAL_VOUCHING_SECRET", "test-secret")
	t.Setenv("SOCIAL_VOUCHING_SEED_IDS", "seed-1, seed-2 ,,seed-3")

	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatalf("BuildDependencies: %v", err)
	}
	m, ok := deps.Registry.Get(socialvouching.MethodID)
	if !ok {
		t.Fatal("social-vouching-graph not registered")
	}
	if md := m.Metadata(); md.Strength >= 50 {
		t.Errorf("social-vouching-graph strength = %d, want < 50 (supplementary)", md.Strength)
	}

	var vouchRoute *methodRoute
	for i := range deps.MethodRoutes {
		if deps.MethodRoutes[i].MethodID == socialvouching.MethodID {
			vouchRoute = &deps.MethodRoutes[i]
		}
	}
	if vouchRoute == nil {
		t.Fatal("no MethodRoute registered for social-vouching-graph")
	}
	if vouchRoute.Path != "vouch" || vouchRoute.Method != http.MethodPost || vouchRoute.Handler == nil {
		t.Errorf("unexpected vouch route: %+v", vouchRoute)
	}
}
