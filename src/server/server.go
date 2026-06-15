package server

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	emailmethod "github.com/sagearbor/personhood/src/methods/email"
	govidmethod "github.com/sagearbor/personhood/src/methods/government-id-liveness"
	plaidmethod "github.com/sagearbor/personhood/src/methods/plaid-bank-link"
	smsmethod "github.com/sagearbor/personhood/src/methods/sms"
	"github.com/sagearbor/personhood/src/registry"
)

// Server is the Personhood reference issuer.
//
// It owns:
//   - the method Registry (built from injected method plugins),
//   - the credential Issuer (Ed25519 signing key),
//   - the in-memory SessionStore,
//   - the DID document material (issuer DID, verification method, public key),
//   - optional method-specific HTTP routes (e.g. Persona webhook).
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

	// methodRoutes carries additional HTTP handlers a method plugin needs
	// the server to host (e.g. third-party webhook receivers). Populated by
	// the registry-builder helpers; mounted under /v1/methods/{id}/<path>
	// in Router().
	methodRoutes []methodRoute

	// nowFunc is overridden in tests to make ceremony timestamps deterministic.
	// Default is time.Now.UTC.
	nowFunc func() time.Time

	// credentialLifetime governs how far in the future ExpirationDate is set
	// on each issued credential. v0.1 default: 365 days.
	credentialLifetime time.Duration
}

// methodRoute describes one HTTP handler a method plugin owns. The server
// mounts it at /v1/methods/{MethodID}/{Path}.
type methodRoute struct {
	MethodID string
	Path     string // e.g. "webhook"
	Method   string // "GET" or "POST"
	Handler  http.Handler
}

// Dependencies bundles the injectable services NewServer needs. Use the
// helpers BuildDefaultMethods + NewDefaultDependencies for a stock v0.1
// deployment; tests construct Dependencies directly with fakes.
type Dependencies struct {
	// Registry is the method registry the server consults. Required.
	Registry *registry.Registry

	// MethodRoutes carries any extra HTTP handlers method plugins own
	// (e.g. Persona's webhook receiver). Empty for a registry that only
	// holds email + sms.
	MethodRoutes []methodRoute
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
		methodRoutes:       deps.MethodRoutes,
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
// implementations (e.g. SendGrid for email, Twilio for SMS — see PR #3) and
// any extra anchor methods (e.g. government-id-liveness — see
// BuildDependencies).
func DefaultMethods(magicLinkBaseURL string) (*registry.Registry, error) {
	reg := registry.New()

	// Sender selection is delegated to the method packages' env-aware
	// factories so build tags (`-tags sendgrid` / `-tags twilio`) and env
	// vars together decide between LogSender and the real vendor sender.
	emailMethod := emailmethod.NewMethod(
		emailmethod.NewSenderFromEnv(),
		magicLinkBaseURL,
		emailmethod.NewInMemoryStore(),
	)
	if err := reg.Register(emailMethod); err != nil {
		return nil, fmt.Errorf("register email: %w", err)
	}

	smsMethodPlugin := smsmethod.NewMethod(
		smsmethod.NewSenderFromEnv(),
		smsmethod.NewInMemoryStore(),
	)
	if err := reg.Register(smsMethodPlugin); err != nil {
		return nil, fmt.Errorf("register sms: %w", err)
	}
	return reg, nil
}

// BuildDependencies assembles the full Dependencies struct for a v0.1
// deployment by:
//   - registering email + sms (always, with LogSender unless real-sender
//     PR #3 is applied),
//   - registering government-id-liveness when PERSONA_API_KEY +
//     PERSONA_TEMPLATE_ID + PERSONA_WEBHOOK_SECRET are all set, and
//     declaring its webhook route so Router() can mount it.
//
// magicLinkBaseURL is the absolute URL the email method's magic links should
// resolve to.
//
// returnURL, if non-empty, is appended to the Persona hosted flow as
// redirect-uri so the user lands back on the web app after completing
// verification. Pass "" to omit.
func BuildDependencies(magicLinkBaseURL, returnURL string) (Dependencies, error) {
	reg, err := DefaultMethods(magicLinkBaseURL)
	if err != nil {
		return Dependencies{}, err
	}
	deps := Dependencies{Registry: reg}

	apiKey := os.Getenv("PERSONA_API_KEY")
	templateID := os.Getenv("PERSONA_TEMPLATE_ID")
	webhookSecret := os.Getenv("PERSONA_WEBHOOK_SECRET")
	envID := os.Getenv("PERSONA_ENVIRONMENT_ID")
	if apiKey != "" && templateID != "" && webhookSecret != "" {
		client, err := govidmethod.NewPersonaClient(apiKey, templateID, envID, nil)
		if err != nil {
			return Dependencies{}, fmt.Errorf("government-id-liveness: persona client: %w", err)
		}
		gov := govidmethod.NewMethod(govidmethod.Config{
			PersonaClient: client,
			Store:         govidmethod.NewInMemoryStore(),
			ReturnURL:     returnURL,
		})
		if err := reg.Register(gov); err != nil {
			return Dependencies{}, fmt.Errorf("register government-id-liveness: %w", err)
		}
		deps.MethodRoutes = append(deps.MethodRoutes, methodRoute{
			MethodID: govidmethod.MethodID,
			Path:     "webhook",
			Method:   http.MethodPost,
			Handler:  gov.WebhookHandler(webhookSecret, nil),
		})
	}

	// Register plaid-bank-link (anchor #3) when PLAID_CLIENT_ID + PLAID_SECRET
	// + PLAID_WEBHOOK_SECRET are all set. PLAID_ENV selects sandbox (default)
	// vs production; PLAID_TEMPLATE_ID is optional.
	plaidClientID := os.Getenv("PLAID_CLIENT_ID")
	plaidSecret := os.Getenv("PLAID_SECRET")
	plaidWebhookSecret := os.Getenv("PLAID_WEBHOOK_SECRET")
	if plaidClientID != "" && plaidSecret != "" && plaidWebhookSecret != "" {
		baseURL := plaidmethod.PlaidBaseURLSandbox
		if os.Getenv("PLAID_ENV") == "production" {
			baseURL = plaidmethod.PlaidBaseURLProduction
		}
		client, err := plaidmethod.NewPlaidClient(plaidClientID, plaidSecret, baseURL, nil)
		if err != nil {
			return Dependencies{}, fmt.Errorf("plaid-bank-link: plaid client: %w", err)
		}
		client.TemplateID = os.Getenv("PLAID_TEMPLATE_ID")
		plaid := plaidmethod.NewMethod(plaidmethod.Config{
			PlaidClient: client,
			Store:       plaidmethod.NewInMemoryStore(),
		})
		if err := reg.Register(plaid); err != nil {
			return Dependencies{}, fmt.Errorf("register plaid-bank-link: %w", err)
		}
		deps.MethodRoutes = append(deps.MethodRoutes, methodRoute{
			MethodID: plaidmethod.MethodID,
			Path:     "webhook",
			Method:   http.MethodPost,
			Handler:  plaid.WebhookHandler(plaidWebhookSecret, nil),
		})
	}
	return deps, nil
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
