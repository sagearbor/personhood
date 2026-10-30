package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"github.com/sagearbor/personhood/pkg/redisclient"
)

// Redis keys for RedisRevocationStore. They mirror the Firestore collections
// in revocation.go, one key per document.
const (
	redisStatusSlotPrefix = "personhood:status-slot:"
	redisCredStatusPrefix = "personhood:credential-status:"
	redisStatusListKey    = "personhood:status-list:default"
)

// RedisRevocationStore persists slots and revocations in Redis, for issuers
// that run outside Google Cloud (scripts/issuer-kit). It is durable only as
// far as the Redis server is: the kit runs Redis with append-only-file
// persistence on a volume, so a restart keeps every slot and revocation.
// Without persistence a restart would forget revocations, and reuse slots
// that older credentials still point at.
//
//   - personhood:status-slot:<index>: claimed with SET NX, so two issuances
//     can never share a slot.
//   - personhood:credential-status:<sha256(credential id)>: {index}.
//   - personhood:status-list:default: the sorted revoked indices.
//
// Revoke is a read-modify-write of the list key under a process-wide mutex,
// the same single-instance assumption as FirestoreRevocationStore.
type RedisRevocationStore struct {
	client *redisclient.Client
	mu     sync.Mutex
}

func NewRedisRevocationStore(client *redisclient.Client) *RedisRevocationStore {
	return &RedisRevocationStore{client: client}
}

// redisSetNX stores value under key only if key is absent. created reports
// whether this call wrote it.
func redisSetNX(ctx context.Context, client *redisclient.Client, key string, value []byte) (created bool, err error) {
	reply, err := client.Do(ctx, "SET", key, string(value), "NX")
	if err != nil {
		return false, err
	}
	return reply.Type != redisclient.ReplyNil, nil
}

func (s *RedisRevocationStore) Allocate(ctx context.Context) (int, error) {
	for i := 0; i < maxAllocateAttempts; i++ {
		idx, err := randomSlot()
		if err != nil {
			return 0, err
		}
		created, err := redisSetNX(ctx, s.client, redisStatusSlotPrefix+strconv.Itoa(idx), []byte("1"))
		if err != nil {
			return 0, fmt.Errorf("server: claim status slot: %w", err)
		}
		if created {
			return idx, nil
		}
	}
	return 0, errors.New("server: status list has no free slot after repeated tries")
}

func (s *RedisRevocationStore) Bind(ctx context.Context, index int, credentialID string) error {
	b, err := json.Marshal(credStatusRecord{CredentialID: credentialID, Index: index})
	if err != nil {
		return fmt.Errorf("server: marshal credential status: %w", err)
	}
	if err := s.client.Set(ctx, redisCredStatusPrefix+credentialDocID(credentialID), b, 0); err != nil {
		return fmt.Errorf("server: bind status slot: %w", err)
	}
	return nil
}

func (s *RedisRevocationStore) readList(ctx context.Context) (statusListRecord, error) {
	raw, found, err := s.client.Get(ctx, redisStatusListKey)
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

func (s *RedisRevocationStore) Revoke(ctx context.Context, credentialID string) (int, bool, error) {
	raw, found, err := s.client.Get(ctx, redisCredStatusPrefix+credentialDocID(credentialID))
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
	if err := s.client.Set(ctx, redisStatusListKey, b, 0); err != nil {
		return 0, false, fmt.Errorf("server: write status list: %w", err)
	}
	return cs.Index, false, nil
}

func (s *RedisRevocationStore) Revoked(ctx context.Context) ([]int, error) {
	list, err := s.readList(ctx)
	if err != nil {
		return nil, err
	}
	if list.Revoked == nil {
		list.Revoked = []int{}
	}
	return list.Revoked, nil
}
