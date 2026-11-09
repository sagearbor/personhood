package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
	"github.com/sagearbor/personhood/pkg/redisclient"
)

// statusListSize is the number of slots in the issuer's default Status List
// 2021 bitstring (131,072 bits, the W3C-recommended minimum, 16 KiB).
const statusListSize = 131_072

// maxAllocateAttempts bounds how many random slots Allocate tries before
// giving up. With the list a few percent full a collision is rare, so
// running out means the list is nearly full and needs a second list.
const maxAllocateAttempts = 16

// ErrCredentialNotFound is returned by RevocationStore.Revoke when the
// credential ID was never bound to a status-list slot (issued before
// revocation existed, or by another issuer).
var ErrCredentialNotFound = errors.New("server: credential has no status-list entry")

// RevocationStore tracks which status-list slot each issued credential owns
// and which slots are revoked.
//
// Slots are chosen at random rather than sequentially: a sequential index
// would tell anyone holding two credentials which was issued first and
// roughly how many people enrolled between them. The W3C Status List spec
// recommends random assignment for that reason.
type RevocationStore interface {
	// Allocate claims an unused slot. Bind must follow once the credential
	// ID is known; an allocated-but-unbound slot simply stays unused.
	Allocate(ctx context.Context) (int, error)
	// Bind records that credentialID owns slot index.
	Bind(ctx context.Context, index int, credentialID string) error
	// Revoke sets the credential's bit. alreadyRevoked is true when the bit
	// was already set; that is not an error.
	Revoke(ctx context.Context, credentialID string) (index int, alreadyRevoked bool, err error)
	// Revoked returns the revoked slots in ascending order.
	Revoked(ctx context.Context) ([]int, error)
}

// NewRevocationStoreFromEnv returns a Firestore-backed store when
// FIRESTORE_PROJECT_ID is set, a Redis-backed one when REDIS_URL is set
// (the Redis server must persist to disk, as the issuer kit's does), else an
// in-memory one that forgets revocations on restart.
func NewRevocationStoreFromEnv() (RevocationStore, error) {
	if projectID := os.Getenv("FIRESTORE_PROJECT_ID"); projectID != "" {
		client, err := firestoreclient.New(projectID)
		if err != nil {
			return nil, fmt.Errorf("server: FIRESTORE_PROJECT_ID: %w", err)
		}
		return NewFirestoreRevocationStore(client), nil
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		client, err := redisclient.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("server: REDIS_URL: %w", err)
		}
		return NewRedisRevocationStore(client), nil
	}
	return NewInMemoryRevocationStore(), nil
}

func randomSlot() (int, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("server: random status slot: %w", err)
	}
	return int(binary.BigEndian.Uint32(b[:]) % statusListSize), nil
}

// ----------------------------------------------------------------------------
// InMemoryRevocationStore
// ----------------------------------------------------------------------------

// InMemoryRevocationStore keeps slots and revocations in process memory.
// For local development and tests only: revocations are lost on restart.
type InMemoryRevocationStore struct {
	mu      sync.Mutex
	used    map[int]bool
	byCred  map[string]int
	revoked map[int]bool
}

func NewInMemoryRevocationStore() *InMemoryRevocationStore {
	return &InMemoryRevocationStore{used: map[int]bool{}, byCred: map[string]int{}, revoked: map[int]bool{}}
}

func (s *InMemoryRevocationStore) Allocate(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < maxAllocateAttempts; i++ {
		idx, err := randomSlot()
		if err != nil {
			return 0, err
		}
		if !s.used[idx] {
			s.used[idx] = true
			return idx, nil
		}
	}
	return 0, errors.New("server: status list has no free slot after repeated tries")
}

func (s *InMemoryRevocationStore) Bind(_ context.Context, index int, credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byCred[credentialID] = index
	return nil
}

func (s *InMemoryRevocationStore) Revoke(_ context.Context, credentialID string) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.byCred[credentialID]
	if !ok {
		return 0, false, ErrCredentialNotFound
	}
	already := s.revoked[idx]
	s.revoked[idx] = true
	return idx, already, nil
}

func (s *InMemoryRevocationStore) Revoked(context.Context) ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, len(s.revoked))
	for idx := range s.revoked {
		out = append(out, idx)
	}
	sort.Ints(out)
	return out, nil
}

// ----------------------------------------------------------------------------
// FirestoreRevocationStore
// ----------------------------------------------------------------------------

const (
	firestoreStatusSlotCollection = "personhood-status-slots"
	firestoreCredStatusCollection = "personhood-credential-status"
	firestoreStatusListCollection = "personhood-status-lists"
	firestoreDefaultStatusListID  = "default"
	revokedCacheTTL               = 30 * time.Second
)

// FirestoreRevocationStore persists slots and revocations in Firestore:
//
//   - personhood-status-slots/<index>: claimed with a create-only write, so
//     two issuances can never share a slot.
//   - personhood-credential-status/<sha256(credential id)>: {index}.
//   - personhood-status-lists/default: the sorted revoked indices.
//
// Revoke is a read-modify-write of the list document under a process-wide
// mutex. That is safe while the issuer runs as one instance
// (--max-instances 1); with more instances two concurrent revocations
// could lose one, and this needs a transaction first. Revocations are rare
// admin actions, so the cost is acceptable for now.
//
// Revoked is read on every status-list request, so it is cached for
// revokedCacheTTL and invalidated by this instance's own Revoke.
type FirestoreRevocationStore struct {
	client *firestoreclient.Client

	mu          sync.Mutex
	cache       []int
	cacheExpiry time.Time
}

func NewFirestoreRevocationStore(client *firestoreclient.Client) *FirestoreRevocationStore {
	return &FirestoreRevocationStore{client: client}
}

type credStatusRecord struct {
	CredentialID string `json:"credential_id"`
	Index        int    `json:"index"`
}

type statusListRecord struct {
	Revoked []int `json:"revoked"`
}

func credentialDocID(credentialID string) string {
	sum := sha256.Sum256([]byte(credentialID))
	return hex.EncodeToString(sum[:])
}

func (s *FirestoreRevocationStore) Allocate(ctx context.Context) (int, error) {
	for i := 0; i < maxAllocateAttempts; i++ {
		idx, err := randomSlot()
		if err != nil {
			return 0, err
		}
		created, err := s.client.Create(ctx, firestoreStatusSlotCollection, strconv.Itoa(idx), []byte("{}"))
		if err != nil {
			return 0, fmt.Errorf("server: claim status slot: %w", err)
		}
		if created {
			return idx, nil
		}
	}
	return 0, errors.New("server: status list has no free slot after repeated tries")
}

func (s *FirestoreRevocationStore) Bind(ctx context.Context, index int, credentialID string) error {
	b, err := json.Marshal(credStatusRecord{CredentialID: credentialID, Index: index})
	if err != nil {
		return fmt.Errorf("server: marshal credential status: %w", err)
	}
	if err := s.client.Set(ctx, firestoreCredStatusCollection, credentialDocID(credentialID), b, 0); err != nil {
		return fmt.Errorf("server: bind status slot: %w", err)
	}
	return nil
}

func (s *FirestoreRevocationStore) readList(ctx context.Context) (statusListRecord, error) {
	raw, found, err := s.client.Get(ctx, firestoreStatusListCollection, firestoreDefaultStatusListID)
	if err != nil {
		return statusListRecord{}, fmt.Errorf("server: read status list: %w", err)
	}
	var rec statusListRecord
	if found {
		if err := json.Unmarshal(raw, &rec); err != nil {
			return statusListRecord{}, fmt.Errorf("server: parse status list: %w", err)
		}
	}
	return rec, nil
}

func (s *FirestoreRevocationStore) Revoke(ctx context.Context, credentialID string) (int, bool, error) {
	raw, found, err := s.client.Get(ctx, firestoreCredStatusCollection, credentialDocID(credentialID))
	if err != nil {
		return 0, false, fmt.Errorf("server: read credential status: %w", err)
	}
	if !found {
		return 0, false, ErrCredentialNotFound
	}
	var cs credStatusRecord
	if err := json.Unmarshal(raw, &cs); err != nil {
		return 0, false, fmt.Errorf("server: parse credential status: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.readList(ctx)
	if err != nil {
		return 0, false, err
	}
	for _, idx := range list.Revoked {
		if idx == cs.Index {
			return cs.Index, true, nil
		}
	}
	list.Revoked = append(list.Revoked, cs.Index)
	sort.Ints(list.Revoked)
	b, err := json.Marshal(list)
	if err != nil {
		return 0, false, fmt.Errorf("server: marshal status list: %w", err)
	}
	if err := s.client.Set(ctx, firestoreStatusListCollection, firestoreDefaultStatusListID, b, 0); err != nil {
		return 0, false, fmt.Errorf("server: write status list: %w", err)
	}
	s.cache, s.cacheExpiry = nil, time.Time{}
	return cs.Index, false, nil
}

func (s *FirestoreRevocationStore) Revoked(ctx context.Context) ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache != nil && time.Now().Before(s.cacheExpiry) {
		return s.cache, nil
	}
	list, err := s.readList(ctx)
	if err != nil {
		return nil, err
	}
	if list.Revoked == nil {
		list.Revoked = []int{}
	}
	s.cache, s.cacheExpiry = list.Revoked, time.Now().Add(revokedCacheTTL)
	return s.cache, nil
}
