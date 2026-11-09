package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// assertMarkIssuedOnce races n MarkIssued calls for one fresh session and
// requires exactly one to win; the rest must get ErrSessionAlreadyIssued.
func assertMarkIssuedOnce(t *testing.T, store SessionStore) {
	t.Helper()
	view, err := store.Create(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = store.MarkIssued(view.ID, fmt.Sprintf("urn:test:cred:%d", i))
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrSessionAlreadyIssued):
		default:
			t.Fatalf("MarkIssued: unexpected error %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d concurrent MarkIssued calls succeeded, want exactly 1", wins)
	}
}

func TestInMemorySessionStore_MarkIssuedOnce(t *testing.T) {
	assertMarkIssuedOnce(t, NewInMemorySessionStore(time.Hour))
}

func TestIntegration_FirestoreSessionStore_MarkIssuedOnce(t *testing.T) {
	assertMarkIssuedOnce(t, NewFirestoreSessionStore(firestoreTestClient(t), time.Hour))
}

func TestIntegration_RedisSessionStore_MarkIssuedOnce(t *testing.T) {
	assertMarkIssuedOnce(t, NewRedisSessionStore(redisTestClient(t), time.Hour))
}

// TestIntegration_ConcurrentIssueMintsOnce fires concurrent issue requests
// for one verified session: exactly one gets a credential, the rest 409.
func TestIntegration_ConcurrentIssueMintsOnce(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServer(t)
	defer cleanup()
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{"platform": "web"}), &start)
	var begin beginMethodResponse
	mustPOST(t, base+"/v1/methods/email/begin", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"user_input": "race@example.com",
	}), &begin)
	_, link, _ := emailSender.lastSent()
	resp, err := http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = postIssueStatus(t, base, start.SessionID)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
		default:
			t.Errorf("issue: unexpected status %d", c)
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent issue calls returned a credential, want exactly 1 (codes %v)", ok, codes)
	}
}

func postIssueStatus(t *testing.T, base, sessionID string) int {
	resp, err := http.Post(base+"/v1/credentials/issue", "application/json",
		bytes.NewReader(mustJSON(t, map[string]any{"session_id": sessionID})))
	if err != nil {
		t.Error(err)
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}
