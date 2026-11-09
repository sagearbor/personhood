package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
	"github.com/sagearbor/personhood/pkg/redisclient"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// Durable selfie-anchor accumulators (SELFIE_ANCHOR=1).
//
// The accumulator is the set the selfie anchor dedupes against: one record
// per enrolled face, holding the fuzzy extractor's helper data and the
// commitment, never a photo or descriptor. In memory it is forgotten on
// every restart, after which every face could enroll again as a new
// person, so a deployment keeps it in Firestore or persistent Redis.
//
// FindDuplicate reads the whole set on every enrollment (the fuzzy match
// has no index). That is fine for a test cohort of thousands; beyond that
// it needs a locality-sensitive-hash shortlist, and the measured false
// match rate (docs/selfie-anchor.md) caps the useful size well before
// speed does.
//
// What the stored records reveal: the repetition code leaves only 17 secret
// bits per record, so anyone holding a record can recover the 256-bit
// template in about 2^17 hash trials. A template is not a photo, but it
// can be matched against a template computed from any photo of the same
// person. Treat this collection as biometric data.

const (
	firestoreSelfieCollection = "personhood-selfie-accumulator"
	redisSelfieListKey        = "personhood:selfie-accumulator"
)

type selfieRecordDoc struct {
	Helper     []byte    `json:"helper"`
	Commitment string    `json:"commitment"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

func encodeSelfieRecord(rec fuzzyextractorselfie.EnrollmentRecord) ([]byte, error) {
	return json.Marshal(selfieRecordDoc{Helper: rec.Helper, Commitment: rec.Commitment.Hex(), EnrolledAt: rec.EnrolledAt})
}

func decodeSelfieRecord(raw []byte) (fuzzyextractorselfie.EnrollmentRecord, error) {
	var doc selfieRecordDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fuzzyextractorselfie.EnrollmentRecord{}, fmt.Errorf("server: corrupt selfie record: %w", err)
	}
	c, err := hex.DecodeString(doc.Commitment)
	if err != nil || len(c) != len(fuzzyextractorselfie.Commitment{}) {
		return fuzzyextractorselfie.EnrollmentRecord{}, fmt.Errorf("server: corrupt selfie record commitment")
	}
	rec := fuzzyextractorselfie.EnrollmentRecord{Helper: doc.Helper, EnrolledAt: doc.EnrolledAt}
	copy(rec.Commitment[:], c)
	return rec, nil
}

// scanForDuplicate runs the fuzzy-extractor match of template against recs.
func scanForDuplicate(template []byte, recs []fuzzyextractorselfie.EnrollmentRecord) (fuzzyextractorselfie.EnrollmentRecord, bool, error) {
	for _, rec := range recs {
		c, ok, err := fuzzyextractorselfie.Rep(template, rec.Helper)
		if err != nil {
			return fuzzyextractorselfie.EnrollmentRecord{}, false, err
		}
		if ok && c == rec.Commitment {
			return rec, true, nil
		}
	}
	return fuzzyextractorselfie.EnrollmentRecord{}, false, nil
}

// NewSelfieAccumulatorFromEnv picks the store the same way the other
// durable stores do: Firestore when FIRESTORE_PROJECT_ID is set, Redis
// when REDIS_URL is set, else memory (with durable=false so the caller can
// warn).
func NewSelfieAccumulatorFromEnv() (acc fuzzyextractorselfie.Accumulator, durable bool, err error) {
	if projectID := os.Getenv("FIRESTORE_PROJECT_ID"); projectID != "" {
		client, err := firestoreclient.New(projectID)
		if err != nil {
			return nil, false, fmt.Errorf("server: FIRESTORE_PROJECT_ID: %w", err)
		}
		return &FirestoreSelfieAccumulator{client: client}, true, nil
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		client, err := redisclient.ParseURL(redisURL)
		if err != nil {
			return nil, false, fmt.Errorf("server: REDIS_URL: %w", err)
		}
		return &RedisSelfieAccumulator{client: client}, true, nil
	}
	return fuzzyextractorselfie.NewInMemoryAccumulator(), false, nil
}

// FirestoreSelfieAccumulator keeps one document per enrolled face, id =
// commitment hex.
type FirestoreSelfieAccumulator struct {
	client *firestoreclient.Client
	// collection defaults to the selfie anchor's; the document anchor
	// keeps its face index in its own collection.
	collection string
}

func (a *FirestoreSelfieAccumulator) coll() string {
	if a.collection != "" {
		return a.collection
	}
	return firestoreSelfieCollection
}

func NewFirestoreSelfieAccumulator(client *firestoreclient.Client) *FirestoreSelfieAccumulator {
	return &FirestoreSelfieAccumulator{client: client}
}

func (a *FirestoreSelfieAccumulator) all(ctx context.Context) ([]fuzzyextractorselfie.EnrollmentRecord, error) {
	docs, err := a.client.List(ctx, a.coll())
	if err != nil {
		return nil, err
	}
	recs := make([]fuzzyextractorselfie.EnrollmentRecord, 0, len(docs))
	for _, d := range docs {
		rec, err := decodeSelfieRecord(d.Data)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

func (a *FirestoreSelfieAccumulator) FindDuplicate(ctx context.Context, template []byte) (fuzzyextractorselfie.EnrollmentRecord, bool, error) {
	recs, err := a.all(ctx)
	if err != nil {
		return fuzzyextractorselfie.EnrollmentRecord{}, false, err
	}
	return scanForDuplicate(template, recs)
}

func (a *FirestoreSelfieAccumulator) Add(ctx context.Context, rec fuzzyextractorselfie.EnrollmentRecord) error {
	b, err := encodeSelfieRecord(rec)
	if err != nil {
		return err
	}
	created, err := a.client.Create(ctx, a.coll(), rec.Commitment.Hex(), b)
	if err != nil {
		return err
	}
	if !created {
		// Commitments are SHA-256 of fresh random seeds; a collision means
		// a store fault, not a second person.
		return fmt.Errorf("server: selfie commitment already stored")
	}
	return nil
}

func (a *FirestoreSelfieAccumulator) Count(ctx context.Context) (int, error) {
	docs, err := a.client.List(ctx, a.coll())
	return len(docs), err
}

// RedisSelfieAccumulator keeps the records in one Redis list (RPUSH /
// LRANGE). Only as durable as the Redis server's persistence.
type RedisSelfieAccumulator struct {
	client *redisclient.Client
	// listKey defaults to the selfie anchor's (see FirestoreSelfieAccumulator.collection).
	listKey string
}

func (a *RedisSelfieAccumulator) key() string {
	if a.listKey != "" {
		return a.listKey
	}
	return redisSelfieListKey
}

func NewRedisSelfieAccumulator(client *redisclient.Client) *RedisSelfieAccumulator {
	return &RedisSelfieAccumulator{client: client}
}

func (a *RedisSelfieAccumulator) FindDuplicate(ctx context.Context, template []byte) (fuzzyextractorselfie.EnrollmentRecord, bool, error) {
	reply, err := a.client.Do(ctx, "LRANGE", a.key(), "0", "-1")
	if err != nil {
		return fuzzyextractorselfie.EnrollmentRecord{}, false, fmt.Errorf("server: selfie LRANGE: %w", err)
	}
	recs := make([]fuzzyextractorselfie.EnrollmentRecord, 0, len(reply.Array))
	for _, item := range reply.Array {
		rec, err := decodeSelfieRecord([]byte(item.Str))
		if err != nil {
			return fuzzyextractorselfie.EnrollmentRecord{}, false, err
		}
		recs = append(recs, rec)
	}
	return scanForDuplicate(template, recs)
}

func (a *RedisSelfieAccumulator) Add(ctx context.Context, rec fuzzyextractorselfie.EnrollmentRecord) error {
	b, err := encodeSelfieRecord(rec)
	if err != nil {
		return err
	}
	if _, err := a.client.Do(ctx, "RPUSH", a.key(), string(b)); err != nil {
		return fmt.Errorf("server: selfie RPUSH: %w", err)
	}
	return nil
}

func (a *RedisSelfieAccumulator) Count(ctx context.Context) (int, error) {
	reply, err := a.client.Do(ctx, "LLEN", a.key())
	if err != nil {
		return 0, err
	}
	return int(reply.Int), nil
}

// SelfieAnchorStrength is the strength the selfie anchor advertises under
// SELFIE_ANCHOR=1: the anchor floor, not the catalog's 70. A browser
// cannot prove its camera feed is real and the measured false-match rate
// limits dedupe to small cohorts (docs/selfie-anchor.md), so 50 keeps it
// usable as a test anchor while flagging that it is the weakest one.
const SelfieAnchorStrength = 50
