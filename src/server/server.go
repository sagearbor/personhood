package server

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	emailmethod "github.com/sagearbor/personhood/src/methods/email"
	smsmethod "github.com/sagearbor/personhood/src/methods/sms"
	"github.com/sagearbor/personhood/src/registry"
)

// Server is the Personhood reference issuer.
//
// It owns:
//   - the method Registry (built from injected method plugins),
//   - the credential Issuer (Ed25519 signing key),
//   - the in-memory SessionStore,
//   - the DID document material (issuer DID, verification method, public key).
//
// One Server value is constructed at startup and shared across handlers.
type Server struct {
	cfg Config

	issuerDID          types.DID
	issuerVMethodID    string
	issuerPublicKey    ed25519.PublicKey
	statusListURL      string

	registry *registry.Registry
	issuer   *credential.Issuer
	sessions *SessionStore

	// nowFunc is overridden in tests to make ceremony timestamps deterministic.
	// Default is time.Now.UTC.
	nowFunc func() time.Time

	// credentialLifetime governs how far in the future ExpirationDate is set
	// on each issued credential. v0.1 default: 365 days.
	credentialLifetime time.Duration
}

// Dependencies bundles the injectable services NewServer needs. Use the
// helpers BuildDefaultMethods + NewDefaultDependencies for a stock v0.1
// deployment; tests construct Dependencies directly with fakes.
type Dependencies struct {
	// Registry is the method registry the server consults. Required.
	Registry *registry.Registry
}

// NewServer constructs a Server from cfg and deps. It returns an error if cfg
// fails Validate() or if deps.Registry is nil.
//
// NewServer does NOT spin up the listener; call Server.Router() and pass to
// net/http yourself.
func NewServer(cfg Config, deps Dependencies) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if deps.Registry == nil {
		return nil, errors.New("server: Dependencies.Registry is required")
	}

	issuerDID, err := IssuerDIDFromPublicURL(cfg.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("server: derive issuer DID: %w", err)
	}
	vMethod := IssuerVerificationMethod(issuerDID, "key-1")
	pub, ok := cfg.IssuerPrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("server: issuer key did not expose an Ed25519 public half")
	}

	statusListURL, err := absoluteURL(cfg.PublicURL, "/v1/status-list/default")
	if err != nil {
		return nil, fmt.Errorf("server: derive status list URL: %w", err)
	}

	issuer := credential.NewIssuer(issuerDID, "key-1", cfg.IssuerPrivateKey, statusListURL)

	return &Server{
		cfg:                cfg,
		issuerDID:          issuerDID,
		issuerVMethodID:    vMethod,
		issuerPublicKey:    pub,
		statusListURL:      statusListURL,
		registry:           deps.Registry,
		issuer:             issuer,
		sessions:           NewSessionStore(cfg.SessionTTL),
		nowFunc:            func() time.Time { return time.Now().UTC() },
		credentialLifetime: 365 * 24 * time.Hour,
	}, nil
}

// IssuerDID returns the issuer's did:web identifier. Exposed for tests and
// integrators that want to construct a MapResolver entry.
func (s *Server) IssuerDID() types.DID { return s.issuerDID }

// IssuerPublicKey returns the Ed25519 public key the issuer signs with.
func (s *Server) IssuerPublicKey() ed25519.PublicKey { return s.issuerPublicKey }

// StatusListURL returns the absolute URL of the issuer's default status list.
func (s *Server) StatusListURL() string { return s.statusListURL }

// Registry returns the method registry this server was constructed with.
// Handlers consult it; tests use it to inspect registered methods.
func (s *Server) Registry() *registry.Registry { return s.registry }

// SetNowFunc overrides time.Now for ceremonies that the server runs on
// behalf of methods. Only useful in tests.
func (s *Server) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		s.nowFunc = fn
	}
}

// SetCredentialLifetime overrides the default credential expiration window.
// Useful in tests; production should keep the 365-day default.
func (s *Server) SetCredentialLifetime(d time.Duration) {
	if d > 0 {
		s.credentialLifetime = d
	}
}

// ----------------------------------------------------------------------------
// Default plugin wiring
// ----------------------------------------------------------------------------

// DefaultMethods returns a Registry populated with the v0.1 supplementary
// methods (email + SMS), each pointed at LogSender so they run without
// vendor credentials.
//
// magicLinkBaseURL is the absolute URL the email method's magic links should
// land on (typically PublicURL + "/v1/methods/email/verify").
//
// Production callers should build their own registry with real Sender
// implementations (e.g. SendGrid for email, Twilio for SMS — see PR #3).
func DefaultMethods(magicLinkBaseURL string) (*registry.Registry, error) {
	reg := registry.New()

	emailMethod := emailmethod.NewMethod(
		&emailmethod.LogSender{},
		magicLinkBaseURL,
		emailmethod.NewInMemoryStore(),
	)
	if err := reg.Register(emailMethod); err != nil {
		return nil, fmt.Errorf("register email: %w", err)
	}

	smsMethodPlugin := smsmethod.NewMethod(
		&smsmethod.LogSender{},
		smsmethod.NewInMemoryStore(),
	)
	if err := reg.Register(smsMethodPlugin); err != nil {
		return nil, fmt.Errorf("register sms: %w", err)
	}
	return reg, nil
}

// absoluteURL joins base + path safely. Returns an error if base is not a
// valid URL.
func absoluteURL(base, p string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	relative, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	return u.ResolveReference(relative).String(), nil
}
