package server

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/sagearbor/personhood/src/credential"
	"github.com/sagearbor/personhood/src/credential/pq"
)

// With ISSUER_MLDSA_SK set, issued credentials carry a pqProof that verifies
// (RequirePQ) under the ML-DSA key the DID document publishes, and the
// Ed25519 key stays the first verification method.
func TestIntegration_PQProofIssuedAndPublished(t *testing.T) {
	seed := make([]byte, pq.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	base, srv, emailSender, _, cleanup := newTestServerWith(t, func(c *Config) { c.IssuerPQSeed = seed })
	defer cleanup()

	var cfg serverConfigResponse
	mustGET(t, base+"/v1/config", &cfg)
	if !cfg.PQProof {
		t.Error("/v1/config pq_proof = false, want true")
	}

	var doc IssuerDIDDocument
	mustGET(t, base+"/.well-known/did.json", &doc)
	if len(doc.VerificationMethod) != 2 || doc.VerificationMethod[0].PublicKeyJwk["crv"] != "Ed25519" {
		t.Fatalf("verificationMethod = %+v, want Ed25519 first then ML-DSA", doc.VerificationMethod)
	}
	jwk := doc.VerificationMethod[1].PublicKeyJwk
	if jwk["kty"] != "AKP" || jwk["alg"] != "ML-DSA-65" {
		t.Fatalf("pq jwk = %v", jwk)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk["pub"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var pqPub mldsa65.PublicKey
	if err := pqPub.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}

	cred := issueEmailCredential(t, base, emailSender)
	if cred.Proof.PQProof == nil || cred.Proof.PQProof.VerificationMethod != doc.VerificationMethod[1].ID {
		t.Fatalf("pqProof = %+v, want one naming %s", cred.Proof.PQProof, doc.VerificationMethod[1].ID)
	}
	v := credential.NewVerifier(credential.MapResolver{srv.IssuerDID(): srv.IssuerPublicKey()})
	v.PQ, v.RequirePQ = pq.Verifier{Resolver: pq.MapResolver{srv.IssuerDID(): &pqPub}}, true
	if err := v.Verify(context.Background(), cred); err != nil {
		t.Fatalf("hybrid verify: %v", err)
	}
}

func TestIntegration_NoPQByDefault(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServer(t)
	defer cleanup()
	var cfg serverConfigResponse
	mustGET(t, base+"/v1/config", &cfg)
	var doc IssuerDIDDocument
	mustGET(t, base+"/.well-known/did.json", &doc)
	cred := issueEmailCredential(t, base, emailSender)
	if cfg.PQProof || len(doc.VerificationMethod) != 1 || cred.Proof.PQProof != nil {
		t.Errorf("pq_proof=%v vms=%d pqProof=%v, want PQ fully off", cfg.PQProof, len(doc.VerificationMethod), cred.Proof.PQProof)
	}
}

func TestLoadConfig_ISSUER_MLDSA_SK(t *testing.T) {
	t.Setenv("ISSUER_ED25519_SK_B64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("ISSUER_MLDSA_SK", base64.StdEncoding.EncodeToString(make([]byte, 31)))
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Error("31-byte ISSUER_MLDSA_SK accepted")
	}
	t.Setenv("ISSUER_MLDSA_SK", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	cfg, err := LoadConfigFromEnv()
	if err != nil || len(cfg.IssuerPQSeed) != 32 {
		t.Errorf("32-byte seed: err=%v len=%d", err, len(cfg.IssuerPQSeed))
	}
}
