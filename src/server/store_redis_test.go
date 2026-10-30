package server

import (
	"context"
	"testing"
)

func TestIntegration_RedisRevocationStore(t *testing.T) {
	s := NewRedisRevocationStore(redisTestClient(t))
	ctx := context.Background()
	idx, err := s.Allocate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Allocate(ctx)
	if err != nil || other == idx {
		t.Fatalf("second Allocate: %d %v, want a different slot than %d", other, err, idx)
	}
	credID := "urn:personhood:credential:test:" + t.Name() + ":" + uniqueSuffix()
	if err := s.Bind(ctx, idx, credID); err != nil {
		t.Fatal(err)
	}
	got, already, err := s.Revoke(ctx, credID)
	if err != nil || already || got != idx {
		t.Fatalf("Revoke: idx=%d already=%v err=%v, want %d", got, already, err, idx)
	}
	if _, already, _ := s.Revoke(ctx, credID); !already {
		t.Error("second Revoke: want already_revoked")
	}
	// A second store on the same Redis (a restarted issuer) sees the revocation.
	revoked, err := NewRedisRevocationStore(redisTestClient(t)).Revoked(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range revoked {
		found = found || r == idx
	}
	if !found {
		t.Errorf("Revoked() = %v, missing %d", revoked, idx)
	}
	if _, _, err := s.Revoke(ctx, "urn:never-issued"); err != ErrCredentialNotFound {
		t.Errorf("unknown credential: err=%v, want ErrCredentialNotFound", err)
	}
}

func TestIntegration_RedisIdentifierStore(t *testing.T) {
	st := NewRedisIdentifierStore(redisTestClient(t))
	ctx := context.Background()
	k, _ := newIdentifierKeyer(testKey(t))
	key := k.Key(identifierKindEmail, "it-"+uniqueSuffix()+"@example.com")

	if _, found, err := st.Lookup(ctx, key); err != nil || found {
		t.Fatalf("fresh key: found=%v err=%v", found, err)
	}
	if got, err := st.GetOrCreate(ctx, key, "seed-one"); err != nil || got != "seed-one" {
		t.Fatalf("create: %q %v", got, err)
	}
	if got, err := st.GetOrCreate(ctx, key, "seed-two"); err != nil || got != "seed-one" {
		t.Fatalf("second create must return the first seed: %q %v", got, err)
	}
	if _, err := st.GetOrCreate(ctx, "not-a-key", "x"); err == nil {
		t.Fatal("malformed key must be refused before reaching Redis")
	}
}

func TestStoresFromEnv_SelectRedis(t *testing.T) {
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "redis://127.0.0.1:1") // never dialed by the factories
	rev, err := NewRevocationStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rev.(*RedisRevocationStore); !ok {
		t.Errorf("revocations: got %T, want *RedisRevocationStore", rev)
	}
	ids, err := NewIdentifierStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids.(*RedisIdentifierStore); !ok {
		t.Errorf("identifiers: got %T, want *RedisIdentifierStore", ids)
	}

	t.Setenv("REDIS_URL", "")
	if rev, _ := NewRevocationStoreFromEnv(); rev == nil {
		t.Fatal("nil store")
	} else if _, ok := rev.(*InMemoryRevocationStore); !ok {
		t.Errorf("no REDIS_URL: got %T, want in-memory", rev)
	}
}
