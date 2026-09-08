// Command verify-credential checks a Personhood credential the way an
// integrator (e.g. OpenLine) would: issuer signature, revocation, and policy.
//
// It is the last step of scripts/e2e-email.sh and a handy way to inspect a
// credential a friend sends you.
//
// Trust the issuer either by fetching its DID document:
//
//	go run ./tools/verify-credential \
//	    -cred friend.json \
//	    -policy docs/policies/round1-email.yaml \
//	    -issuer-url https://personhood.fly.dev
//
// or by pinning the key explicitly (what OpenLine governance does):
//
//	go run ./tools/verify-credential -cred friend.json -policy p.yaml \
//	    -issuer-did did:web:personhood.fly.dev -issuer-pub <base64url x from did.json>
//
// Exit status: 0 = OK, 1 = credential rejected (see "code"), 2 = could not
// complete the check (bad flags, unreachable issuer, ...).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	personhood "github.com/sagearbor/personhood/sdk/go"
)

type output struct {
	OK         bool                 `json:"ok"`
	Code       types.EvaluationCode `json:"code"`
	Human      string               `json:"human"`
	Details    map[string]any       `json:"details,omitempty"`
	Nullifier  string               `json:"nullifier,omitempty"`
	Issuer     types.DID            `json:"issuer"`
	Holder     types.DID            `json:"holder"`
	Anchor     *string              `json:"anchor_method_id"`
	Methods    []string             `json:"verified_methods"`
	PolicyID   string               `json:"policy_id"`
	IssuerKeyX string               `json:"issuer_public_key_b64url"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-credential", flag.ContinueOnError)
	fs.SetOutput(stderr)
	credPath := fs.String("cred", "", "path to the credential JSON (required)")
	policyPath := fs.String("policy", "", "path to the policy YAML or JSON (required)")
	issuerURL := fs.String("issuer-url", "", "issuer base URL; its /.well-known/did.json supplies the trusted key")
	issuerDID := fs.String("issuer-did", "", "trusted issuer DID (use with -issuer-pub instead of -issuer-url)")
	issuerPub := fs.String("issuer-pub", "", "trusted issuer Ed25519 public key, base64url (the JWK 'x' value)")
	skipRevoke := fs.Bool("skip-revocation", false, "do not fetch the Status List 2021 (offline check)")
	timeout := fs.Duration("timeout", 10*time.Second, "HTTP timeout for did.json / status-list fetches")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *credPath == "" || *policyPath == "" {
		fmt.Fprintln(stderr, "verify-credential: -cred and -policy are required")
		fs.Usage()
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	hc := &http.Client{Timeout: *timeout}

	credRaw, err := os.ReadFile(*credPath)
	if err != nil {
		return fail(stderr, err)
	}
	cred, err := personhood.ParseCredential(credRaw)
	if err != nil {
		return fail(stderr, fmt.Errorf("parse credential: %w", err))
	}
	polRaw, err := os.ReadFile(*policyPath)
	if err != nil {
		return fail(stderr, err)
	}
	var pol types.Policy
	if strings.HasSuffix(strings.ToLower(*policyPath), ".json") {
		pol, err = personhood.ParsePolicyJSON(polRaw)
	} else {
		pol, err = personhood.ParsePolicyYAML(polRaw)
	}
	if err != nil {
		return fail(stderr, fmt.Errorf("parse policy: %w", err))
	}

	// Trusted issuer: explicit pin wins; otherwise fetch the DID document.
	var trustedDID types.DID
	var pub ed25519.PublicKey
	switch {
	case *issuerDID != "" && *issuerPub != "":
		trustedDID = types.DID(*issuerDID)
		pub, err = decodeKey(*issuerPub)
		if err != nil {
			return fail(stderr, fmt.Errorf("-issuer-pub: %w", err))
		}
	case *issuerURL != "":
		trustedDID, pub, err = fetchIssuerKey(ctx, hc, *issuerURL)
		if err != nil {
			return fail(stderr, err)
		}
	default:
		fmt.Fprintln(stderr, "verify-credential: pass -issuer-url, or -issuer-did with -issuer-pub")
		return 2
	}

	opts := []personhood.Option{personhood.WithHTTPClient(hc)}
	if *skipRevoke {
		opts = append(opts, personhood.WithoutRevocationCheck())
	}
	v := personhood.NewVerifier(personhood.TrustedIssuers(map[types.DID]ed25519.PublicKey{trustedDID: pub}), opts...)
	res, err := v.Verify(ctx, cred, pol)
	if err != nil {
		return fail(stderr, fmt.Errorf("verify: %w", err))
	}

	out := output{
		OK: res.OK, Code: res.Code, Human: res.Human, Details: res.Details, Nullifier: res.Nullifier,
		Issuer: cred.Issuer, Holder: cred.CredentialSubject.ID,
		Anchor: cred.CredentialSubject.AnchorMethodID, PolicyID: pol.PolicyID,
		IssuerKeyX: base64.RawURLEncoding.EncodeToString(pub),
	}
	for _, m := range cred.CredentialSubject.VerifiedMethods {
		out.Methods = append(out.Methods, m.MethodID)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	if res.OK {
		return 0
	}
	return 1
}

func fail(w io.Writer, err error) int {
	fmt.Fprintf(w, "verify-credential: %v\n", err)
	return 2
}

// decodeKey accepts base64url or standard base64, padded or not.
func decodeKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
			}
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, errors.New("not valid base64")
}

// didDoc is the subset of the issuer's DID document we need.
type didDoc struct {
	ID                 types.DID `json:"id"`
	VerificationMethod []struct {
		ID           string            `json:"id"`
		Type         string            `json:"type"`
		PublicKeyJwk map[string]string `json:"publicKeyJwk"`
	} `json:"verificationMethod"`
}

// fetchIssuerKey GETs <issuerURL>/.well-known/did.json and returns the DID
// plus the Ed25519 public key from its first OKP/Ed25519 JWK.
func fetchIssuerKey(ctx context.Context, hc *http.Client, issuerURL string) (types.DID, ed25519.PublicKey, error) {
	u := strings.TrimRight(issuerURL, "/") + "/.well-known/did.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Accept", "application/did+json, application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("fetch %s: status %d", u, resp.StatusCode)
	}
	var doc didDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", nil, fmt.Errorf("parse %s: %w", u, err)
	}
	for _, vm := range doc.VerificationMethod {
		if vm.PublicKeyJwk["kty"] == "OKP" && vm.PublicKeyJwk["crv"] == "Ed25519" && vm.PublicKeyJwk["x"] != "" {
			pub, err := decodeKey(vm.PublicKeyJwk["x"])
			if err != nil {
				return "", nil, fmt.Errorf("%s: bad JWK x: %w", u, err)
			}
			return doc.ID, pub, nil
		}
	}
	return "", nil, fmt.Errorf("%s: no Ed25519 OKP JWK in verificationMethod", u)
}
