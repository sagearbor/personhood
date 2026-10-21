package server

import (
	"net/http"
	"testing"

	ipasnmethod "github.com/sagearbor/personhood/src/methods/ip-asn-reputation"
)

// The static always-clean ip-asn provider used to be registered by default,
// which let a client earn 10 points (more than round1-email's bar) with no
// email at all.
func TestBuildDependencies_IPASNOffByDefault(t *testing.T) {
	t.Setenv("IP_ASN_REPUTATION", "")
	deps, err := BuildDependencies("http://localhost:8080/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(ipasnmethod.MethodID); ok {
		t.Fatal("ip-asn-reputation is registered by default; it must be opt-in")
	}

	t.Setenv("IP_ASN_REPUTATION", "static")
	deps, err = BuildDependencies("http://localhost:8080/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(ipasnmethod.MethodID); !ok {
		t.Fatal("IP_ASN_REPUTATION=static should register ip-asn-reputation")
	}
}

// The server, not the client, says which IP is being judged.
func TestIntegration_IPASNIgnoresClientSuppliedIP(t *testing.T) {
	base, _, _, _, cleanup := newTestServerWithDeps(t, nil, func(d *Dependencies) {
		bad := ipasnmethod.NewStaticProvider(map[string]ipasnmethod.Reputation{
			"127.0.0.1": {IsDatacenter: true},
		})
		if err := d.Registry.Register(ipasnmethod.NewMethod(ipasnmethod.DefaultConfig(bad))); err != nil {
			t.Fatal(err)
		}
	})
	defer cleanup()

	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{"platform": "web"}), &start)
	code, body := postRaw(t, base+"/v1/methods/ip-asn-reputation/complete", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"response":   map[string]any{"type": "ip-asn", "payload": map[string]any{"ip": "1.2.3.4"}},
	}))
	if code != http.StatusOK {
		t.Fatalf("complete: %d %v", code, body)
	}
	result, _ := body["result"].(map[string]any)
	if result["success"] == true || result["error_reason"] != "ip_datacenter" {
		t.Fatalf("want failure ip_datacenter from the server-seen 127.0.0.1, got %v", body)
	}
}
