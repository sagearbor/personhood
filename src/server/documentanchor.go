package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
	"github.com/sagearbor/personhood/pkg/redisclient"
	documentchip "github.com/sagearbor/personhood/src/methods/document-chip"
	"github.com/sagearbor/personhood/src/methods/document-chip/signedqr"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// Document anchor (docs/document-chip-anchor.md): ePassport / eID chips and
// signed-QR national IDs, behind DOCUMENT_CHIP_ANCHOR=1 (default off).
//
//	DOCUMENT_CHIP_ANCHOR=1              register document-chip and
//	                                    document-signed-qr (needs
//	                                    IDENTIFIER_HMAC_KEY: uniqueness is a
//	                                    keyed hash of the document)
//	DOCUMENT_CHIP_ALLOW_PASSIVE_ONLY=1  accept chips without Active
//	                                    Authentication (strength 70 not 80)
//	DOCUMENT_CHIP_CSCA_PEM=<file>       extra CSCA certificates (PEM), e.g.
//	                                    from the ICAO PKD, on top of the
//	                                    embedded German master list
//	DOCUMENT_QR_FORMATS_DIR=<dir>       extra signed-QR format JSON + keys
//	DOCUMENT_FACE_BIND_URL=<url>        the web app's /face-bind page the
//	                                    wallet opens for the face match
//
// Documents enrolled through either method are unique per document via the
// identifier-seed machinery (identifier.go, kind "document"). A face that
// matches an identity enrolled with a different document is flagged for
// review (GET /v1/admin/document-reviews), never refused.

// documentAnchorDeps is what BuildDependencies hands NewServer.
type documentAnchorDeps struct {
	known   *knownIdentifierHook
	reviews documentchip.ReviewQueue
}

// knownIdentifierHook lets the methods, built before the Server, ask the
// Server's identifier store whether a document was enrolled before.
type knownIdentifierHook struct {
	mu sync.RWMutex
	fn func(ctx context.Context, identifier string) (bool, error)
}

func (h *knownIdentifierHook) call(ctx context.Context, identifier string) (bool, error) {
	h.mu.RLock()
	fn := h.fn
	h.mu.RUnlock()
	if fn == nil {
		return false, nil
	}
	return fn(ctx, identifier)
}

// documentAnchorFromEnv builds both methods, or returns nils when
// DOCUMENT_CHIP_ANCHOR is not "1".
func documentAnchorFromEnv() (*documentchip.ChipMethod, *documentchip.QRMethod, *documentAnchorDeps, error) {
	if os.Getenv("DOCUMENT_CHIP_ANCHOR") != "1" {
		return nil, nil, nil, nil
	}
	if strings.TrimSpace(os.Getenv(IdentifierKeyEnv)) == "" {
		return nil, nil, nil, fmt.Errorf("DOCUMENT_CHIP_ANCHOR=1 needs %s: without it one document could enroll any number of times", IdentifierKeyEnv)
	}
	trust, infos, err := documentchip.DefaultTrust()
	if err != nil {
		return nil, nil, nil, err
	}
	if p := strings.TrimSpace(os.Getenv("DOCUMENT_CHIP_CSCA_PEM")); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("DOCUMENT_CHIP_CSCA_PEM: %w", err)
		}
		added, skipped := trust.AddPEM(raw)
		log.Printf("document-chip: %d extra CSCA certificates from %s (%d unparsed)", added, p, skipped)
	}
	for _, info := range infos {
		log.Printf("document-chip: master list from %s: %d CSCA certificates (%d unparsed)", info.Signer, info.Certificates, info.Skipped)
	}
	log.Printf("document-chip: CSCA trust covers %d states", len(trust.Countries()))

	formats, err := signedqr.Builtin()
	if err != nil {
		return nil, nil, nil, err
	}
	if dir := strings.TrimSpace(os.Getenv("DOCUMENT_QR_FORMATS_DIR")); dir != "" {
		if err := formats.LoadFS(os.DirFS(dir)); err != nil {
			return nil, nil, nil, fmt.Errorf("DOCUMENT_QR_FORMATS_DIR: %w", err)
		}
	}

	faces, reviews, durable, err := documentStoresFromEnv()
	if err != nil {
		return nil, nil, nil, err
	}
	if !durable {
		log.Printf("WARNING: DOCUMENT_CHIP_ANCHOR=1 without FIRESTORE_PROJECT_ID or REDIS_URL: the dual-document face index and review queue are in memory")
	}
	hook := &knownIdentifierHook{}
	cfg := documentchip.Config{
		Trust:            trust,
		QRFormats:        formats,
		AllowPassiveOnly: os.Getenv("DOCUMENT_CHIP_ALLOW_PASSIVE_ONLY") == "1",
		FaceBindURL:      strings.TrimSpace(os.Getenv("DOCUMENT_FACE_BIND_URL")),
		Faces:            faces,
		Reviews:          reviews,
		KnownIdentifier:  hook.call,
	}
	onReview := func(rc documentchip.ReviewCase) {
		log.Printf(`{"severity":"NOTICE","message":"document anchor: face matches an identity enrolled with another document; queued for review","review_id":%q,"method":%q,"country":%q}`, rc.ID, rc.MethodID, rc.DocumentCountry)
	}
	return documentchip.NewChipMethod(cfg, onReview), documentchip.NewQRMethod(cfg, onReview),
		&documentAnchorDeps{known: hook, reviews: reviews}, nil
}

// wireDocumentAnchor connects the methods to this server's identifier store.
func (s *Server) wireDocumentAnchor(d *documentAnchorDeps) error {
	if s.identifierKeys == nil || s.identifiers == nil {
		return errors.New("server: the document anchor needs IDENTIFIER_HMAC_KEY")
	}
	d.known.mu.Lock()
	d.known.fn = func(ctx context.Context, identifier string) (bool, error) {
		_, found, err := s.identifiers.Lookup(ctx, s.identifierKeys.Key(identifierKindDocument, identifier))
		return found, err
	}
	d.known.mu.Unlock()
	s.documentReviews = d.reviews
	return nil
}

// handleAdminDocumentReviews lists dual-document review cases.
func (s *Server) handleAdminDocumentReviews(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid admin bearer token is required")
		return
	}
	if s.documentReviews == nil {
		writeError(w, http.StatusNotFound, "not_enabled", "the document anchor is not enabled")
		return
	}
	cases, err := s.documentReviews.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cases": cases})
}

const (
	firestoreDocumentFaceCollection   = "personhood-document-faces"
	redisDocumentFaceListKey          = "personhood:document-faces"
	firestoreDocumentReviewCollection = "personhood-document-reviews"
	redisDocumentReviewListKey        = "personhood:document-reviews"
)

// documentStoresFromEnv returns the face index and review queue, durable
// when Firestore or Redis is configured. The face index is separate from
// the selfie anchor's accumulator so that enrolling a document never makes
// the selfie anchor refuse the same person later.
func documentStoresFromEnv() (documentchip.FaceIndex, documentchip.ReviewQueue, bool, error) {
	if projectID := os.Getenv("FIRESTORE_PROJECT_ID"); projectID != "" {
		client, err := firestoreclient.New(projectID)
		if err != nil {
			return nil, nil, false, fmt.Errorf("server: FIRESTORE_PROJECT_ID: %w", err)
		}
		return &FirestoreSelfieAccumulator{client: client, collection: firestoreDocumentFaceCollection},
			&firestoreReviewQueue{client: client}, true, nil
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		client, err := redisclient.ParseURL(redisURL)
		if err != nil {
			return nil, nil, false, fmt.Errorf("server: REDIS_URL: %w", err)
		}
		return &RedisSelfieAccumulator{client: client, listKey: redisDocumentFaceListKey},
			&redisReviewQueue{client: client}, true, nil
	}
	return fuzzyextractorselfie.NewInMemoryAccumulator(), &documentchip.InMemoryReviewQueue{}, false, nil
}

type firestoreReviewQueue struct{ client *firestoreclient.Client }

func (q *firestoreReviewQueue) Add(ctx context.Context, c documentchip.ReviewCase) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = q.client.Create(ctx, firestoreDocumentReviewCollection, c.ID, b)
	return err
}

func (q *firestoreReviewQueue) List(ctx context.Context) ([]documentchip.ReviewCase, error) {
	docs, err := q.client.List(ctx, firestoreDocumentReviewCollection)
	if err != nil {
		return nil, err
	}
	out := make([]documentchip.ReviewCase, 0, len(docs))
	for _, d := range docs {
		var c documentchip.ReviewCase
		if err := json.Unmarshal(d.Data, &c); err != nil {
			return nil, fmt.Errorf("server: corrupt review case: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

type redisReviewQueue struct{ client *redisclient.Client }

func (q *redisReviewQueue) Add(ctx context.Context, c documentchip.ReviewCase) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = q.client.Do(ctx, "RPUSH", redisDocumentReviewListKey, string(b))
	return err
}

func (q *redisReviewQueue) List(ctx context.Context) ([]documentchip.ReviewCase, error) {
	reply, err := q.client.Do(ctx, "LRANGE", redisDocumentReviewListKey, "0", "-1")
	if err != nil {
		return nil, err
	}
	out := make([]documentchip.ReviewCase, 0, len(reply.Array))
	for _, item := range reply.Array {
		var c documentchip.ReviewCase
		if err := json.Unmarshal([]byte(item.Str), &c); err != nil {
			return nil, fmt.Errorf("server: corrupt review case: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}
