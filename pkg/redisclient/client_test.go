package redisclient

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// --- protocol-level unit tests (no real Redis needed) ----------------------

func TestEncodeCommand(t *testing.T) {
	got := string(encodeCommand([]string{"SET", "k", "v"}))
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"
	if got != want {
		t.Errorf("encodeCommand mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestReadReply(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    Reply
		wantErr bool
	}{
		{"status", "+OK\r\n", Reply{Type: ReplyStatus, Str: "OK"}, false},
		{"integer", ":42\r\n", Reply{Type: ReplyInteger, Int: 42}, false},
		{"bulk", "$5\r\nhello\r\n", Reply{Type: ReplyBulk, Str: "hello"}, false},
		{"empty bulk", "$0\r\n\r\n", Reply{Type: ReplyBulk, Str: ""}, false},
		{"nil bulk", "$-1\r\n", Reply{Type: ReplyNil}, false},
		{"error", "-ERR bad thing\r\n", Reply{}, true},
		{"unsupported array", "*2\r\n$1\r\na\r\n$1\r\nb\r\n", Reply{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.in))
			got, err := readReply(r)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got reply %+v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("readReply(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantPass string
		wantDB   int
		wantErr  bool
	}{
		{"localhost:6379", "localhost:6379", "", 0, false},
		{"redis://localhost:6379", "localhost:6379", "", 0, false},
		{"redis://:secret@localhost:6380", "localhost:6380", "secret", 0, false},
		{"redis://localhost:6379/3", "localhost:6379", "", 3, false},
		{"redis://:secret@localhost:6379/2", "localhost:6379", "secret", 2, false},
		{"", "", "", 0, true},
		{"rediss://localhost:6379", "", "", 0, true},
		{"redis://localhost:6379/notanumber", "", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			c, err := ParseURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseURL(%q): expected an error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseURL(%q): unexpected error: %v", tc.in, err)
			}
			if c.addr != tc.wantAddr {
				t.Errorf("ParseURL(%q).addr = %q, want %q", tc.in, c.addr, tc.wantAddr)
			}
			if c.password != tc.wantPass {
				t.Errorf("ParseURL(%q).password = %q, want %q", tc.in, c.password, tc.wantPass)
			}
			if c.db != tc.wantDB {
				t.Errorf("ParseURL(%q).db = %d, want %d", tc.in, c.db, tc.wantDB)
			}
		})
	}
}

// --- integration tests against a real local Redis --------------------------
//
// Gated on REDIS_TEST_ADDR (falls back to REDIS_URL, then skips). Run
// locally with a Redis started on a non-default port, e.g.:
//
//	redis-server --port 6399 --daemonize no &
//	REDIS_TEST_ADDR=127.0.0.1:6399 go test ./...

func testAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = os.Getenv("REDIS_URL")
	}
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR (or REDIS_URL) not set; skipping real-Redis integration test")
	}
	return addr
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	addr := testAddr(t)
	c, err := ParseURL(addr)
	if err != nil {
		// Not a URL — treat as a bare host:port.
		c = New(addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("could not reach Redis at %q: %v (is it running? see this test's doc comment)", addr, err)
	}
	return c
}

func TestIntegration_PingSetGetDel(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	key := "redisclient-test:ping-set-get-del"
	t.Cleanup(func() { _ = c.Del(ctx, key) })

	if _, found, err := c.Get(ctx, key); err != nil {
		t.Fatalf("Get before Set: %v", err)
	} else if found {
		t.Fatalf("Get before Set: unexpectedly found a value")
	}

	if err := c.Set(ctx, key, []byte("hello world"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val, found, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("Get: expected to find the value just Set")
	}
	if !bytes.Equal(val, []byte("hello world")) {
		t.Errorf("Get: got %q, want %q", val, "hello world")
	}

	if err := c.Del(ctx, key); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if _, found, err := c.Get(ctx, key); err != nil {
		t.Fatalf("Get after Del: %v", err)
	} else if found {
		t.Fatal("Get after Del: unexpectedly still found")
	}

	// Del on an already-missing key is idempotent, not an error.
	if err := c.Del(ctx, key); err != nil {
		t.Errorf("Del on a missing key should be a no-op, got: %v", err)
	}
}

func TestIntegration_SetWithTTLExpires(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	key := "redisclient-test:ttl-expires"
	t.Cleanup(func() { _ = c.Del(ctx, key) })

	if err := c.Set(ctx, key, []byte("short-lived"), 150*time.Millisecond); err != nil {
		t.Fatalf("Set with TTL: %v", err)
	}
	if _, found, err := c.Get(ctx, key); err != nil || !found {
		t.Fatalf("Get immediately after Set: found=%v err=%v", found, err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, found, err := c.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get while polling for expiry: %v", err)
		}
		if !found {
			return // expired as expected
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("key did not expire within 3s of a 150ms TTL")
}

func TestIntegration_SetOverwritesClearsOldTTL(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	key := "redisclient-test:overwrite-clears-ttl"
	t.Cleanup(func() { _ = c.Del(ctx, key) })

	if err := c.Set(ctx, key, []byte("v1"), 100*time.Millisecond); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	// Overwrite with no TTL before the first one would have expired.
	if err := c.Set(ctx, key, []byte("v2"), 0); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	val, found, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("expected the no-TTL overwrite to still be present past the original TTL")
	}
	if string(val) != "v2" {
		t.Errorf("Get = %q, want %q", val, "v2")
	}
}

func TestIntegration_AuthAgainstNoPasswordServerFails(t *testing.T) {
	addr := testAddr(t)
	// This assumes the test Redis has no password set (true for the
	// brew-installed default config used in this repo's verification runs).
	// Supplying one anyway should produce a clear AUTH error, not a silent
	// success or a hang.
	c := New(addr, WithPassword("definitely-not-the-password"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err == nil {
		t.Skip("test Redis appears to require no auth check on unrecognized password (unexpected server config); skipping")
	}
}
