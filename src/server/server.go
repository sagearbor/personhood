package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	appattestmethod "github.com/sagearbor/personhood/src/methods/app-attest-device"
	captchamethod "github.com/sagearbor/personhood/src/methods/captcha-turnstile"
	emailmethod "github.com/sagearbor/personhood/src/methods/email"
	emailtiermethod "github.com/sagearbor/personhood/src/methods/email-tier"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
	govidmethod "github.com/sagearbor/personhood/src/methods/government-id-liveness"
	ipasnmethod "github.com/sagearbor/personhood/src/methods/ip-asn-reputation"
	paidcardmethod "github.com/sagearbor/personhood/src/methods/paid-billing-card"
	carriertiermethod "github.com/sagearbor/personhood/src/methods/phone-carrier-tier"
	plaidmethod "github.com/sagearbor/personhood/src/methods/plaid-bank-link"
	smsmethod "github.com/sagearbor/personhood/src/methods/sms"
	socialvouching "github.com/sagearbor/personhood/src/methods/social-vouching"
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

	issuerDID       types.DID
	issuerVMethodID string
	issuerPublicKey ed25519.PublicKey
	statusListURL   string

	registry *registry.Registry
	issuer   *credential.Issuer
	sessions SessionStore

	// methodRoutes carries additional HTTP handlers a method plugin needs
	// the server to host (e.g. third-party webhook receivers). Populated by
	// the registry-builder helpers; mounted under /v1/methods/{id}/<path>
	// in Router().
	methodRoutes []methodRoute

	// emailDelivery names the email backend the registered `email` method
	// sends through — one of email.SenderKind* ("log", "smtp", "sendgrid",
	// "unknown"). Reported by GET /v1/config so an operator (or the web app)
	// can see at a glance whether real mail is leaving the box.
	emailDelivery string

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

	// EmailSenderKind names the email delivery backend the Registry's email
	// method was built with — one of the email.SenderKind* constants.
	// BuildDependencies fills it in from the Sender it actually constructed.
	// Empty (the default, e.g. when a test injects its own Sender) is
	// reported as email.SenderKindUnknown on GET /v1/config.
	EmailSenderKind string
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

	sessions, err := NewSessionStoreFromEnv(cfg.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("server: session store: %w", err)
	}

	emailDelivery := deps.EmailSenderKind
	if emailDelivery == "" {
		emailDelivery = emailmethod.SenderKindUnknown
	}

	return &Server{
		cfg:                cfg,
		emailDelivery:      emailDelivery,
		issuerDID:          issuerDID,
		issuerVMethodID:    vMethod,
		issuerPublicKey:    pub,
		statusListURL:      statusListURL,
		registry:           deps.Registry,
		issuer:             issuer,
		sessions:           sessions,
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
	reg, _, err := defaultMethods(magicLinkBaseURL)
	return reg, err
}

// defaultMethods is DefaultMethods plus the one extra fact BuildDependencies
// needs: which email Sender the env-aware factory actually picked. Returned
// separately rather than calling NewSenderFromEnv a second time, so the
// reported kind can never disagree with the Sender in the registry.
func defaultMethods(magicLinkBaseURL string) (*registry.Registry, string, error) {
	reg := registry.New()

	// Sender selection is delegated to the method packages' env-aware
	// factories so build tags (`-tags sendgrid` / `-tags twilio`) and env
	// vars together decide between LogSender and the real vendor sender.
	// Store selection follows the same pattern: NewTokenStoreFromEnv /
	// NewOTPStoreFromEnv return a Redis-backed store when REDIS_URL is set,
	// an in-memory one (the default) otherwise.
	emailStore, err := emailmethod.NewTokenStoreFromEnv()
	if err != nil {
		return nil, "", fmt.Errorf("email: token store: %w", err)
	}
	emailSender := emailmethod.NewSenderFromEnv()
	emailMethod := emailmethod.NewMethod(
		emailSender,
		magicLinkBaseURL,
		emailStore,
	)
	if err := reg.Register(emailMethod); err != nil {
		return nil, "", fmt.Errorf("register email: %w", err)
	}

	smsStore, err := smsmethod.NewOTPStoreFromEnv()
	if err != nil {
		return nil, "", fmt.Errorf("sms: otp store: %w", err)
	}
	smsMethodPlugin := smsmethod.NewMethod(
		smsmethod.NewSenderFromEnv(),
		smsStore,
	)
	if err := reg.Register(smsMethodPlugin); err != nil {
		return nil, "", fmt.Errorf("register sms: %w", err)
	}
	return reg, emailmethod.SenderKind(emailSender), nil
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
	reg, emailSenderKind, err := defaultMethods(magicLinkBaseURL)
	if err != nil {
		return Dependencies{}, err
	}
	deps := Dependencies{Registry: reg, EmailSenderKind: emailSenderKind}

	apiKey := os.Getenv("PERSONA_API_KEY")
	templateID := os.Getenv("PERSONA_TEMPLATE_ID")
	webhookSecret := os.Getenv("PERSONA_WEBHOOK_SECRET")
	envID := os.Getenv("PERSONA_ENVIRONMENT_ID")
	if apiKey != "" && templateID != "" && webhookSecret != "" {
		client, err := govidmethod.NewPersonaClient(apiKey, templateID, envID, nil)
		if err != nil {
			return Dependencies{}, fmt.Errorf("government-id-liveness: persona client: %w", err)
		}
		govStore, err := govidmethod.NewResultStoreFromEnv()
		if err != nil {
			return Dependencies{}, fmt.Errorf("government-id-liveness: result store: %w", err)
		}
		gov := govidmethod.NewMethod(govidmethod.Config{
			PersonaClient: client,
			Store:         govStore,
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

	// Register the near-free "floor" supplementary methods (checklist #7). They
	// add recency/anti-bot signals to every credential but never substitute for
	// an anchor; integrators require them via docs/policies/default-floor.yaml.
	// None of these has a webhook (they're synchronous begin/complete), so no
	// MethodRoutes are added.

	// ip-asn-reputation: always-on with a default (clean) provider so the floor
	// signal is present out of the box. Production swaps in a real provider
	// (MaxMind / IPQualityScore) via the ReputationProvider interface.
	ipasn := ipasnmethod.NewMethod(ipasnmethod.DefaultConfig(ipasnmethod.NewStaticProvider(nil)))
	if err := reg.Register(ipasn); err != nil {
		return Dependencies{}, fmt.Errorf("register ip-asn-reputation: %w", err)
	}

	// captcha-turnstile: registered when Cloudflare Turnstile keys are present.
	turnstileSiteKey := os.Getenv("TURNSTILE_SITE_KEY")
	turnstileSecret := os.Getenv("TURNSTILE_SECRET_KEY")
	if turnstileSiteKey != "" && turnstileSecret != "" {
		tc, err := captchamethod.NewTurnstileClient(turnstileSiteKey, turnstileSecret, nil)
		if err != nil {
			return Dependencies{}, fmt.Errorf("captcha-turnstile: client: %w", err)
		}
		if err := reg.Register(captchamethod.NewMethod(captchamethod.Config{TurnstileClient: tc})); err != nil {
			return Dependencies{}, fmt.Errorf("register captcha-turnstile: %w", err)
		}
	}

	// app-attest-device: registered when APP_ATTEST_SECRET is set. v0.1 uses the
	// HMAC dev verifier; v0.2 swaps in real Apple App Attest / Play Integrity
	// verification behind the same Verifier interface.
	if appAttestSecret := os.Getenv("APP_ATTEST_SECRET"); appAttestSecret != "" {
		appAttest := appattestmethod.NewMethod(appattestmethod.Config{
			Verifier: appattestmethod.NewHMACDevVerifier(appAttestSecret),
			Store:    appattestmethod.NewInMemoryStore(),
		})
		if err := reg.Register(appAttest); err != nil {
			return Dependencies{}, fmt.Errorf("register app-attest-device: %w", err)
		}
	}

	// paid-billing-card (checklist #9): the strongest single supplementary
	// (strength 35) — a $0 Stripe SetupIntent with 3DS/SCA. Registered when
	// STRIPE_SECRET_KEY + STRIPE_WEBHOOK_SECRET are set; STRIPE_PUBLISHABLE_KEY
	// is passed through to the client so Stripe.js can confirm the card.
	// STRIPE_BASE_URL overrides the API root (default https://api.stripe.com).
	stripeSecret := os.Getenv("STRIPE_SECRET_KEY")
	stripeWebhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if stripeSecret != "" && stripeWebhookSecret != "" {
		baseURL := os.Getenv("STRIPE_BASE_URL")
		if baseURL == "" {
			baseURL = paidcardmethod.StripeBaseURL
		}
		stripeClient, err := paidcardmethod.NewStripeClient(stripeSecret, baseURL, nil)
		if err != nil {
			return Dependencies{}, fmt.Errorf("paid-billing-card: stripe client: %w", err)
		}
		paidCard := paidcardmethod.NewMethod(paidcardmethod.Config{
			StripeClient:   stripeClient,
			Store:          paidcardmethod.NewInMemoryStore(),
			PublishableKey: os.Getenv("STRIPE_PUBLISHABLE_KEY"),
		})
		if err := reg.Register(paidCard); err != nil {
			return Dependencies{}, fmt.Errorf("register paid-billing-card: %w", err)
		}
		deps.MethodRoutes = append(deps.MethodRoutes, methodRoute{
			MethodID: paidcardmethod.MethodID,
			Path:     "webhook",
			Method:   http.MethodPost,
			Handler:  paidCard.WebhookHandler(stripeWebhookSecret, nil),
		})
	}

	// phone-carrier-tier (checklist #8): the strength-28 upgrade for plain SMS
	// (line-type intelligence + SIM-swap/porting via Twilio Lookup). Registered
	// additively alongside `sms` when Twilio credentials are present, so the
	// strength-28 rating is only advertised when the real carrier provider is
	// wired. It reuses the env-aware sms sender (Twilio behind `-tags twilio`,
	// LogSender otherwise) via a thin interface adapter. app/web now prefers
	// this method over plain `sms` whenever the server advertises it (see
	// app/web/lib/tiering.ts); both methods use the same "otp" ceremony shape
	// over the already-parameterized /v1/methods/{id}/begin|complete routes,
	// so no server-side routing change is needed (contrast with email-tier's
	// shared magic-link landing route above).
	if os.Getenv("TWILIO_ACCOUNT_SID") != "" && os.Getenv("TWILIO_AUTH_TOKEN") != "" {
		carrierTier := carriertiermethod.NewMethod(carriertiermethod.Config{
			Sender:   smsTierSenderAdapter{inner: smsmethod.NewSenderFromEnv()},
			Store:    carriertiermethod.NewInMemoryStore(),
			Provider: carriertiermethod.NewProviderFromEnv(),
		})
		if err := reg.Register(carrierTier); err != nil {
			return Dependencies{}, fmt.Errorf("register phone-carrier-tier: %w", err)
		}
	}

	// email-tier (checklist #8): the strength-22 upgrade for plain email
	// (domain reputation + HaveIBeenPwned breach-presence). Registered
	// additively alongside `email` when HIBP_API_KEY is present, so the
	// strength-22 rating is only advertised when the real enrichment provider
	// is wired. It reuses the env-aware email sender (SendGrid behind
	// `-tags sendgrid`, LogSender otherwise) via a thin interface adapter.
	// app/web now prefers this method over plain `email` whenever the server
	// advertises it (see app/web/lib/tiering.ts); both stay registered so a
	// server without HIBP_API_KEY still issues on plain `email`.
	//
	// Magic links for BOTH methods land on the same GET
	// /v1/methods/email/verify route (handleEmailMagicLink), so email-tier's
	// base URL carries an explicit `method=email-tier` query parameter —
	// otherwise the shared handler would default to completing the ceremony
	// against the plain `email` method, and email-tier's token (stored in its
	// own in-memory store) would never be found.
	if os.Getenv("HIBP_API_KEY") != "" {
		emailTierBaseURL := magicLinkBaseURL
		if u, err := url.Parse(magicLinkBaseURL); err == nil {
			q := u.Query()
			q.Set("method", emailtiermethod.MethodID)
			u.RawQuery = q.Encode()
			emailTierBaseURL = u.String()
		}
		emailTier := emailtiermethod.NewMethod(emailtiermethod.Config{
			Sender:   emailTierSenderAdapter{inner: emailmethod.NewSenderFromEnv()},
			BaseURL:  emailTierBaseURL,
			Store:    emailtiermethod.NewInMemoryStore(),
			Provider: emailtiermethod.NewProviderFromEnv(),
		})
		if err := reg.Register(emailTier); err != nil {
			return Dependencies{}, fmt.Errorf("register email-tier: %w", err)
		}
	}

	// fuzzy-extractor-selfie (checklist #10a): the airdrop-test anchor for
	// users with no ID/bank/address. Unlike every other anchor, this wraps
	// NO third-party vendor (see the package doc comment) — there is no
	// vendor credential to gate on, so registration is instead an explicit
	// opt-in via FUZZY_EXTRACTOR_ENABLED, consistent with this repo's
	// pattern of not silently changing what a default deployment advertises.
	if os.Getenv("FUZZY_EXTRACTOR_ENABLED") != "" {
		fuzzy := fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{
			Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator(),
		})
		if err := reg.Register(fuzzy); err != nil {
			return Dependencies{}, fmt.Errorf("register fuzzy-extractor-selfie: %w", err)
		}
	}

	// social-vouching-graph (checklist #10b): the BrightID-style web-of-
	// trust supplementary method. Like fuzzy-extractor-selfie, no vendor is
	// involved; registration is opt-in via SOCIAL_VOUCHING_ENABLED because
	// the method is useless without an operator-configured seed set
	// (SOCIAL_VOUCHING_SEED_IDS, comma-separated, each seeded at trust 1.0)
	// and a shared secret for the dev voucher authenticator
	// (SOCIAL_VOUCHING_SECRET). See src/methods/social-vouching/README.md.
	if os.Getenv("SOCIAL_VOUCHING_ENABLED") != "" {
		secret := os.Getenv("SOCIAL_VOUCHING_SECRET")
		if secret == "" {
			return Dependencies{}, fmt.Errorf("social-vouching-graph: SOCIAL_VOUCHING_ENABLED is set but SOCIAL_VOUCHING_SECRET is empty")
		}
		seeds := make(map[string]float64)
		for _, id := range strings.Split(os.Getenv("SOCIAL_VOUCHING_SEED_IDS"), ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				seeds[id] = 1.0
			}
		}
		vouching := socialvouching.NewMethod(socialvouching.Config{
			Store:         socialvouching.NewInMemoryGraphStore(seeds),
			Authenticator: socialvouching.NewHMACDevAuthenticator(secret),
		})
		if err := reg.Register(vouching); err != nil {
			return Dependencies{}, fmt.Errorf("register social-vouching-graph: %w", err)
		}
		deps.MethodRoutes = append(deps.MethodRoutes, methodRoute{
			MethodID: socialvouching.MethodID,
			Path:     "vouch",
			Method:   http.MethodPost,
			Handler:  vouching.VouchHandler(nil),
		})
	}

	return deps, nil
}

// smsTierSenderAdapter bridges the sms module's Sender to the phone-carrier-tier
// module's Sender. The two interfaces are structurally identical; the adapter
// lets the issuer reuse the existing env-aware (Twilio / Log) SMS delivery for
// the tiered method without duplicating the vendor integration.
type smsTierSenderAdapter struct{ inner smsmethod.Sender }

// Send implements carriertiermethod.Sender.
func (a smsTierSenderAdapter) Send(ctx context.Context, toPhone, body string) error {
	return a.inner.Send(ctx, toPhone, body)
}

// emailTierSenderAdapter bridges the email module's Sender to the email-tier
// module's Sender. The two interfaces are structurally identical; the adapter
// lets the issuer reuse the existing env-aware (SendGrid / Log) email delivery
// for the tiered method without duplicating the vendor integration.
type emailTierSenderAdapter struct{ inner emailmethod.Sender }

// Send implements emailtiermethod.Sender.
func (a emailTierSenderAdapter) Send(ctx context.Context, to, subject, magicLinkURL string) error {
	return a.inner.Send(ctx, to, subject, magicLinkURL)
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
