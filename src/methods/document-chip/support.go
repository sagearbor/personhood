package documentchip

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	fes "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// faceBind is the phone's report of the on-device check that the live
// selfie matches the document's photo (DG2, or the photo inside a signed
// QR). The photo never leaves the phone; this boolean pair does.
//
// It is a claim by the phone. The issuer cannot recompute it, so on its own
// it stops honest mistakes and casual misuse, not a modified app. Combined
// with app-attest-device (a real, locked phone running the real app) it
// becomes much harder to fake.
type faceBind struct {
	Match    bool
	Liveness bool
}

func parseFaceBind(payload map[string]any) (faceBind, bool) {
	raw, ok := payload["face_bind"].(map[string]any)
	if !ok {
		return faceBind{}, false
	}
	m, ok1 := raw["match"].(bool)
	l, ok2 := raw["liveness"].(bool)
	return faceBind{Match: m, Liveness: l}, ok1 && ok2
}

// faceTemplate returns the optional 32-byte selfie template (same format as
// fuzzy-extractor-selfie), or nil.
func faceTemplate(payload map[string]any) ([]byte, error) {
	s, _ := payload["face_template_b64"].(string)
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != fes.TemplateBytes {
		return nil, errors.New("face_template_b64 must be base64 of a 32-byte template")
	}
	return b, nil
}

// b64Field decodes an optional standard-base64 field, bounded in size.
func b64Field(payload map[string]any, key string, max int) ([]byte, error) {
	s, _ := payload[key].(string)
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if base64.StdEncoding.DecodedLen(len(s)) > max {
		return nil, fmt.Errorf("%s too large", key)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s is not base64", key)
	}
	return b, nil
}

// ReviewCase is a document enrollment whose face matched an existing
// identity enrolled with a different document: typically a dual citizen
// with two passports, sometimes a renewed passport, rarely a false face
// match (the face model's false match rate is about 0.2% per pair, see
// docs/selfie-anchor.md). The credential is still issued; a person decides
// whether the two identities are one human. No personal data is recorded.
type ReviewCase struct {
	ID              string    `json:"id"`
	SessionID       string    `json:"session_id"`
	MethodID        string    `json:"method_id"`
	MatchedFaceID   string    `json:"matched_face_commitment"`
	DocumentCountry string    `json:"document_country"`
	CreatedAt       time.Time `json:"created_at"`
}

// ReviewQueue records review cases. Implementations must be safe for
// concurrent use.
type ReviewQueue interface {
	Add(ctx context.Context, c ReviewCase) error
	List(ctx context.Context) ([]ReviewCase, error)
}

// InMemoryReviewQueue is a ReviewQueue for tests and single-process dev.
type InMemoryReviewQueue struct {
	mu    sync.Mutex
	cases []ReviewCase
}

func (q *InMemoryReviewQueue) Add(_ context.Context, c ReviewCase) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.cases = append(q.cases, c)
	return nil
}

func (q *InMemoryReviewQueue) List(_ context.Context) ([]ReviewCase, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]ReviewCase(nil), q.cases...), nil
}

// challengeStore keeps the Active Authentication challenge per session.
type challengeStore struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]challengeEntry
}

type challengeEntry struct {
	nonce []byte
	at    time.Time
}

func newChallengeStore(ttl time.Duration) *challengeStore {
	return &challengeStore{ttl: ttl, m: map[string]challengeEntry{}}
}

func (s *challengeStore) put(session string, nonce []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if now.Sub(v.at) > s.ttl {
			delete(s.m, k)
		}
	}
	s.m[session] = challengeEntry{nonce: nonce, at: now}
}

// take returns and forgets the session's challenge: each challenge answers
// one completion attempt, so a captured chip response cannot be replayed.
func (s *challengeStore) take(session string, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[session]
	delete(s.m, session)
	if !ok || now.Sub(e.at) > s.ttl {
		return nil, false
	}
	return e.nonce, true
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func randomID() string {
	b, _ := randomBytes(16)
	return hex.EncodeToString(b)
}
