package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
	"github.com/sagearbor/personhood/pkg/redisclient"
	"github.com/sagearbor/personhood/pkg/types"
)

// Per-identifier nullifier seeds: one inbox (or phone) is one voter.
//
// Without this, every enrollment got a nullifierBinding derived from the
// holder's device key (NullifierBindingForHolder), and a device key is free
// to regenerate. So one email inbox could enroll again and again and come
// away with a new, independent "human" each time; OpenLine's per-action
// nullifiers could not tell them apart.
//
// Now, when the issuer has an identifier key (IDENTIFIER_HMAC_KEY), every
// email address or phone number a session verifies is normalized and keyed
// with HMAC-SHA256 under that server secret. The keyed hash is the document
// id of a record that holds a random nullifier seed. The first enrollment by
// an identifier creates the seed; every later enrollment by the same
// identifier finds it and gets the SAME seed back, so the credential's
// nullifierBinding commitment, and every per-action nullifier OpenLine
// derives from it, is the same as before. Re-enrolling is a re-issue, not a
// new person.
//
// What is stored: HMAC(key, kind || normalized identifier) -> random seed.
// The raw address or number is never written anywhere by this code. Without
// the server key the hashes cannot be tested against a guessed address.
//
// Residual risk, by design: this binds a credential to an inbox or a phone
// line, not to a human. Someone with many inboxes (a catch-all domain,
// throwaway providers the disposable list misses) or many SIMs still gets
// many credentials. It turns "unlimited credentials per inbox" into "one per
// inbox"; an anchor method (fuzzy-extractor-selfie, whose biometric
// commitment takes precedence over this) is what stops one person holding
// many inboxes.

// IdentifierKeyEnv names the env var holding the identifier HMAC key
// (base64, at least 32 bytes decoded). Unset disables per-identifier seeds.
const IdentifierKeyEnv = "IDENTIFIER_HMAC_KEY"

// minIdentifierKeyBytes is the minimum decoded length of the HMAC key.
const minIdentifierKeyBytes = 32

// Identifier kinds. A session can hold one key of each kind.
const (
	identifierKindEmail = "email"
	identifierKindPhone = "phone"
)

// identifierKindForMethod returns which identifier a method verifies, or ""
// for methods that verify no reusable identifier. Literal ids keep this file
// free of method-package imports; they match each package's MethodID.
func identifierKindForMethod(methodID string) string {
	switch methodID {
	case "email", "email-tier":
		return identifierKindEmail
	case "sms", "phone-carrier-tier":
		return identifierKindPhone
	default:
		return ""
	}
}

// ErrIdentifierFormat is returned by the normalizers for input that cannot
// be reduced to one canonical identifier.
var ErrIdentifierFormat = errors.New("identifier cannot be normalized")

// gmailDomains are the domains whose mailboxes ignore dots in the local part
// (and are the same mailbox under either domain).
var gmailDomains = map[string]bool{"gmail.com": true, "googlemail.com": true}

// NormalizeEmail reduces an email address to the mailbox it delivers to, so
// trivial variants of one inbox count as one identifier:
//
//   - surrounding space trimmed, everything lowercased (local parts are
//     case-insensitive at every mainstream provider);
//   - a "+tag" suffix on the local part dropped (alice+x@ is alice@);
//   - for gmail.com / googlemail.com, dots in the local part dropped and
//     the domain folded to gmail.com (a.l.i.c.e@googlemail.com is
//     alice@gmail.com);
//   - a trailing dot on the domain dropped.
//
// Dropping "+tags" everywhere can, at a provider that allows "+" as an
// ordinary character, merge two real mailboxes into one identifier. That
// fails safe: those two people share one voter seed and the second is told
// they already voted, rather than one person getting many votes.
func NormalizeEmail(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 || strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("%w: not an email address", ErrIdentifierFormat)
	}
	local, domain := s[:at], strings.TrimSuffix(s[at+1:], ".")
	if i := strings.IndexByte(local, '+'); i >= 0 {
		local = local[:i]
	}
	if gmailDomains[domain] {
		local = strings.ReplaceAll(local, ".", "")
		domain = "gmail.com"
	}
	if local == "" || domain == "" {
		return "", fmt.Errorf("%w: empty mailbox or domain", ErrIdentifierFormat)
	}
	return local + "@" + domain, nil
}

// NormalizePhoneE164 reduces a phone number in international form to E.164
// ("+" and 7 to 15 digits, no leading zero). Spaces, dashes, dots and
// parentheses are ignored, and a leading "00" is read as "+". A number with
// no country code is refused: "317 555 0100" and "+1 317 555 0100" would
// otherwise be two identifiers for one phone.
func NormalizePhoneE164(raw string) (string, error) {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		switch r {
		case ' ', '-', '.', '(', ')', ' ':
			continue
		}
		b.WriteRune(r)
	}
	s := b.String()
	if strings.HasPrefix(s, "00") {
		s = "+" + s[2:]
	}
	if !strings.HasPrefix(s, "+") {
		return "", fmt.Errorf("%w: phone number must start with + and the country code", ErrIdentifierFormat)
	}
	digits := s[1:]
	if len(digits) < 7 || len(digits) > 15 || digits[0] == '0' {
		return "", fmt.Errorf("%w: phone number must be 7 to 15 digits after the +", ErrIdentifierFormat)
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("%w: phone number may contain only digits after the +", ErrIdentifierFormat)
		}
	}
	return s, nil
}

// normalizeIdentifier dispatches to the normalizer for kind.
func normalizeIdentifier(kind, raw string) (string, error) {
	switch kind {
	case identifierKindEmail:
		return NormalizeEmail(raw)
	case identifierKindPhone:
		return NormalizePhoneE164(raw)
	default:
		return "", fmt.Errorf("%w: unknown identifier kind %q", ErrIdentifierFormat, kind)
	}
}

// identifierKeyer turns a normalized identifier into its keyed hash.
type identifierKeyer struct {
	key []byte
}

// newIdentifierKeyer validates and wraps an HMAC key.
func newIdentifierKeyer(key []byte) (*identifierKeyer, error) {
	if len(key) < minIdentifierKeyBytes {
		return nil, fmt.Errorf("server: %s must decode to at least %d bytes, got %d", IdentifierKeyEnv, minIdentifierKeyBytes, len(key))
	}
	return &identifierKeyer{key: append([]byte(nil), key...)}, nil
}

// identifierKeyContext domain-separates these HMACs from any other use of
// the key, and versions the derivation.
const identifierKeyContext = "personhood/identifier-key/v1"

// Key returns hex(HMAC-SHA256(key, context || kind || normalized)). The
// parts are NUL-separated; neither kind nor a normalized identifier can
// contain a NUL.
func (k *identifierKeyer) Key(kind, normalized string) string {
	m := hmac.New(sha256.New, k.key)
	m.Write([]byte(identifierKeyContext))
	m.Write([]byte{0})
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(normalized))
	return hex.EncodeToString(m.Sum(nil))
}

// IdentifierStore maps an identifier's keyed hash to its nullifier seed.
// Implementations MUST be safe for concurrent use, and GetOrCreate MUST be
// create-only: two racing callers for one key both get the seed that won.
type IdentifierStore interface {
	// Lookup returns the seed bound to key, if any.
	Lookup(ctx context.Context, key string) (seed string, found bool, err error)
	// GetOrCreate binds seed to key unless key already has a seed, and
	// returns whichever seed key is bound to afterwards.
	GetOrCreate(ctx context.Context, key, seed string) (string, error)
}

// NewIdentifierStoreFromEnv returns a Firestore-backed store when
// FIRESTORE_PROJECT_ID is set, a Redis-backed one when REDIS_URL is set
// (the Redis server must persist to disk, as the issuer kit's does), else an
// in-memory one. Seeds kept only in memory are lost on restart, after which
// every inbox could enroll once more as a "new" person, so a real
// deployment must use Firestore or persistent Redis.
func NewIdentifierStoreFromEnv() (IdentifierStore, error) {
	if projectID := os.Getenv("FIRESTORE_PROJECT_ID"); projectID != "" {
		client, err := firestoreclient.New(projectID)
		if err != nil {
			return nil, fmt.Errorf("server: FIRESTORE_PROJECT_ID: %w", err)
		}
		return NewFirestoreIdentifierStore(client), nil
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		client, err := redisclient.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("server: REDIS_URL: %w", err)
		}
		return NewRedisIdentifierStore(client), nil
	}
	return NewInMemoryIdentifierStore(), nil
}

// InMemoryIdentifierStore keeps seeds in process memory. Dev and tests only.
type InMemoryIdentifierStore struct {
	mu    sync.Mutex
	seeds map[string]string
}

func NewInMemoryIdentifierStore() *InMemoryIdentifierStore {
	return &InMemoryIdentifierStore{seeds: map[string]string{}}
}

func (s *InMemoryIdentifierStore) Lookup(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seed, ok := s.seeds[key]
	return seed, ok, nil
}

func (s *InMemoryIdentifierStore) GetOrCreate(_ context.Context, key, seed string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.seeds[key]; ok {
		return existing, nil
	}
	s.seeds[key] = seed
	return seed, nil
}

// firestoreIdentifierCollection holds one document per identifier: id =
// keyed hash, blob = {"seed": "<hex>"}. Documents never expire.
const firestoreIdentifierCollection = "personhood-identifier-seeds"

// FirestoreIdentifierStore is the production IdentifierStore. Seeds are
// claimed with a create-only write, so two enrollments racing on one inbox
// cannot end up with different seeds.
type FirestoreIdentifierStore struct {
	client *firestoreclient.Client
}

func NewFirestoreIdentifierStore(client *firestoreclient.Client) *FirestoreIdentifierStore {
	return &FirestoreIdentifierStore{client: client}
}

type identifierSeedDoc struct {
	Seed string `json:"seed"`
}

func validIdentifierKey(key string) bool {
	if len(key) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

func (s *FirestoreIdentifierStore) Lookup(ctx context.Context, key string) (string, bool, error) {
	if !validIdentifierKey(key) {
		return "", false, fmt.Errorf("server: malformed identifier key")
	}
	raw, found, err := s.client.Get(ctx, firestoreIdentifierCollection, key)
	if err != nil || !found {
		return "", false, err
	}
	var doc identifierSeedDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Seed == "" {
		return "", false, fmt.Errorf("server: corrupt identifier seed record")
	}
	return doc.Seed, true, nil
}

func (s *FirestoreIdentifierStore) GetOrCreate(ctx context.Context, key, seed string) (string, error) {
	if !validIdentifierKey(key) {
		return "", fmt.Errorf("server: malformed identifier key")
	}
	b, err := json.Marshal(identifierSeedDoc{Seed: seed})
	if err != nil {
		return "", err
	}
	created, err := s.client.Create(ctx, firestoreIdentifierCollection, key, b)
	if err != nil {
		return "", err
	}
	if created {
		return seed, nil
	}
	existing, found, err := s.Lookup(ctx, key)
	if err != nil {
		return "", err
	}
	if !found {
		// Create said the id was taken but it is gone now; records are
		// never deleted by this code, so treat it as a store fault.
		return "", fmt.Errorf("server: identifier seed vanished after create conflict")
	}
	return existing, nil
}

// identifierKindOrder fixes which identifier wins when a session's
// identifiers are already bound to different seeds: a phone line is harder
// to multiply than an inbox, so it goes first.
var identifierKindOrder = map[string]int{identifierKindPhone: 0, identifierKindEmail: 1}

// resolveIdentifierSeed returns the nullifier seed for a session that
// verified the identifiers in keys (kind -> keyed hash).
//
// If any of them already has a seed, that seed is reused (phone before
// email), and it is also bound to the identifiers that had none, so proving
// a new email alongside a known phone links the email to the same person.
// Otherwise a fresh random seed is created and bound to all of them. An
// identifier already bound to a different seed keeps its own binding; the
// credential uses the first one.
func resolveIdentifierSeed(ctx context.Context, store IdentifierStore, keys map[string]string) (string, error) {
	kinds := make([]string, 0, len(keys))
	for kind := range keys {
		kinds = append(kinds, kind)
	}
	if len(kinds) == 0 {
		return "", errors.New("server: no identifier keys to resolve")
	}
	sort.Slice(kinds, func(i, j int) bool {
		oi, okI := identifierKindOrder[kinds[i]]
		oj, okJ := identifierKindOrder[kinds[j]]
		if okI != okJ {
			return okI
		}
		if oi != oj {
			return oi < oj
		}
		return kinds[i] < kinds[j]
	})

	var seed string
	for _, kind := range kinds {
		existing, found, err := store.Lookup(ctx, keys[kind])
		if err != nil {
			return "", fmt.Errorf("server: identifier seed lookup: %w", err)
		}
		if found {
			seed = existing
			break
		}
	}
	if seed == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("server: identifier seed: %w", err)
		}
		seed = hex.EncodeToString(buf)
	}

	for i, kind := range kinds {
		got, err := store.GetOrCreate(ctx, keys[kind], seed)
		if err != nil {
			return "", fmt.Errorf("server: identifier seed bind: %w", err)
		}
		if i == 0 {
			// A concurrent enrollment of the same identifier may have won
			// the create; adopt its seed so both credentials agree.
			seed = got
		}
	}
	return seed, nil
}

// NullifierBindingForIdentifierSeed derives the credential's
// nullifierBinding from a per-identifier seed (see resolveIdentifierSeed).
// Same seed, same commitment, so the same per-context nullifier at every
// integrator. Same v0.1 stub-crypto caveat as NullifierBindingForHolder.
func NullifierBindingForIdentifierSeed(seed string) *types.NullifierBinding {
	if seed == "" {
		return nil
	}
	h := sha256.New()
	h.Write([]byte("personhood-nullifier-binding-identifier-v1"))
	h.Write([]byte(seed))
	return &types.NullifierBinding{
		Commitment: hex.EncodeToString(h.Sum(nil)),
		Curve:      "bn254",
		Scheme:     "pedersen-v1",
	}
}
