// Package firestoreclient is a minimal, dependency-free Firestore client
// (Firestore's plain HTTP/JSON REST API — not the grpc-based
// cloud.google.com/go/firestore SDK) supporting exactly the operations the
// personhood session/token stores need: get one document, upsert one
// document (as a single opaque bytes blob plus an optional expiry
// timestamp), and delete one document.
//
// Hand-rolled deliberately, for the same reason pkg/redisclient is: every
// vendor integration elsewhere in this repo (SendGrid, Twilio, Persona,
// Plaid, Stripe, Redis) is a dependency-free net/http (or net.Conn) client
// rather than an SDK, and pulling in cloud.google.com/go/firestore — which
// drags in grpc, protobuf, and the full google-cloud-go dependency tree —
// into every store module for a handful of get/set/delete calls would break
// that pattern for comparatively little benefit.
//
// Auth: on Cloud Run / GCE, an OAuth2 access token is fetched from the
// metadata server (no key file, no golang.org/x/oauth2 dependency) and
// cached until shortly before it expires. Locally, point
// FIRESTORE_EMULATOR_HOST at a `firebase emulators:start --only firestore`
// (or `firebase emulators:exec --only firestore '<cmd>'`) instance and no
// auth is used at all — this mirrors how every official Firestore client
// library treats that env var, and the emulator's REST surface is
// byte-for-byte the same shape as production's.
package firestoreclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// metadataTokenURL is the GCE/Cloud Run metadata server endpoint that
// returns an OAuth2 access token for the instance's attached service
// account. See
// https://cloud.google.com/compute/docs/metadata/default-metadata-values
const metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

// Client is a minimal Firestore REST client scoped to one project's default
// database. Safe for concurrent use.
type Client struct {
	projectID string
	baseURL   string // e.g. "https://firestore.googleapis.com/v1" or "http://127.0.0.1:8090/v1"
	emulator  bool
	hc        *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// New constructs a Client for projectID.
//
// If the FIRESTORE_EMULATOR_HOST env var is set, requests go to the
// emulator over plain HTTP with no auth. Otherwise requests go to the real
// Firestore REST API over HTTPS with an OAuth2 access token fetched from the
// GCE/Cloud Run metadata server — the Cloud Run service's runtime service
// account needs the `roles/datastore.user` IAM role for this to succeed
// (see scripts/deploy-cloudrun.sh).
func New(projectID string) (*Client, error) {
	if projectID == "" {
		return nil, fmt.Errorf("firestoreclient: projectID is required")
	}
	c := &Client{projectID: projectID, hc: &http.Client{Timeout: 10 * time.Second}}
	if emu := os.Getenv("FIRESTORE_EMULATOR_HOST"); emu != "" {
		c.emulator = true
		c.baseURL = "http://" + emu + "/v1"
	} else {
		c.baseURL = "https://firestore.googleapis.com/v1"
	}
	return c, nil
}

// fsValue is Firestore's typed-value envelope. Only the two variants this
// client uses are represented — see
// https://cloud.google.com/firestore/docs/reference/rest/v1/Value
type fsValue struct {
	BytesValue     string `json:"bytesValue,omitempty"`     // base64-encoded, per the REST API's JSON mapping for the `bytes` type
	TimestampValue string `json:"timestampValue,omitempty"` // RFC3339 UTC, e.g. "2026-09-15T04:05:06.000000000Z"
}

type fsDocument struct {
	Name   string             `json:"name,omitempty"`
	Fields map[string]fsValue `json:"fields,omitempty"`
}

func (c *Client) docURL(collection, id string) string {
	return fmt.Sprintf("%s/projects/%s/databases/(default)/documents/%s/%s",
		c.baseURL, url.PathEscape(c.projectID), url.PathEscape(collection), url.PathEscape(id))
}

// accessToken returns a cached (or freshly fetched) OAuth2 access token for
// the instance's attached service account. Not called at all in emulator
// mode.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		tok := c.token
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataTokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("firestoreclient: build metadata token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("firestoreclient: fetch metadata token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("firestoreclient: read metadata token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("firestoreclient: metadata token request: status %d: %s", resp.StatusCode, body)
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return "", fmt.Errorf("firestoreclient: parse metadata token response: %w", err)
	}
	if tokResp.AccessToken == "" {
		return "", fmt.Errorf("firestoreclient: metadata token response had no access_token")
	}

	c.mu.Lock()
	c.token = tokResp.AccessToken
	// Refresh 60s before actual expiry so a slow request never races an
	// expired token.
	lifetime := time.Duration(tokResp.ExpiresIn) * time.Second
	if lifetime > 90*time.Second {
		lifetime -= 60 * time.Second
	}
	c.tokenExpiry = time.Now().Add(lifetime)
	tok := c.token
	c.mu.Unlock()
	return tok, nil
}

func (c *Client) setAuth(ctx context.Context, req *http.Request) error {
	if c.emulator {
		return nil
	}
	tok, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

// Get returns the raw bytes previously stored for (collection, id), or
// found=false if no such document exists or it has passed the expiry set
// at Set time (an expired document is opportunistically deleted, mirroring
// pkg/redisclient's read-time expiry check).
func (c *Client) Get(ctx context.Context, collection, id string) (data []byte, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.docURL(collection, id), nil)
	if err != nil {
		return nil, false, fmt.Errorf("firestoreclient: build get request: %w", err)
	}
	if err := c.setAuth(ctx, req); err != nil {
		return nil, false, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("firestoreclient: get %s/%s: %w", collection, id, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("firestoreclient: read get response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("firestoreclient: get %s/%s: status %d: %s", collection, id, resp.StatusCode, body)
	}

	var doc fsDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false, fmt.Errorf("firestoreclient: parse document: %w", err)
	}
	blobField, ok := doc.Fields["blob"]
	if !ok {
		return nil, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(blobField.BytesValue)
	if err != nil {
		return nil, false, fmt.Errorf("firestoreclient: decode blob field: %w", err)
	}

	if expField, ok := doc.Fields["expires_at"]; ok && expField.TimestampValue != "" {
		expAt, err := time.Parse(time.RFC3339Nano, expField.TimestampValue)
		if err == nil && time.Now().After(expAt) {
			_ = c.Del(ctx, collection, id)
			return nil, false, nil
		}
	}
	return raw, true, nil
}

// Set upserts (collection, id) with data as its opaque blob. If ttl > 0, the
// document also gets an expires_at field that Get (and only Get — there is
// no server-side TTL policy configured, so an expired-but-unread document
// stays in Firestore until something reads or explicitly deletes it, same
// tradeoff pkg/redisclient documents for its own explicit expiry check)
// enforces on read.
func (c *Client) Set(ctx context.Context, collection, id string, data []byte, ttl time.Duration) error {
	fields := map[string]fsValue{
		"blob": {BytesValue: base64.StdEncoding.EncodeToString(data)},
	}
	if ttl > 0 {
		fields["expires_at"] = fsValue{TimestampValue: time.Now().Add(ttl).UTC().Format(time.RFC3339Nano)}
	}
	body, err := json.Marshal(fsDocument{Fields: fields})
	if err != nil {
		return fmt.Errorf("firestoreclient: marshal document: %w", err)
	}

	// PATCH on a Firestore document path upserts (creates if absent,
	// replaces all fields if present) when no updateMask is given — see
	// https://cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/patch
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.docURL(collection, id), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("firestoreclient: build set request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.setAuth(ctx, req); err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("firestoreclient: set %s/%s: %w", collection, id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firestoreclient: set %s/%s: status %d: %s", collection, id, resp.StatusCode, respBody)
	}
	return nil
}

// Del deletes (collection, id). A missing document is not an error —
// mirrors pkg/redisclient.Client.Del's idempotent-delete semantics.
func (c *Client) Del(ctx context.Context, collection, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.docURL(collection, id), nil)
	if err != nil {
		return fmt.Errorf("firestoreclient: build delete request: %w", err)
	}
	if err := c.setAuth(ctx, req); err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("firestoreclient: delete %s/%s: %w", collection, id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firestoreclient: delete %s/%s: status %d: %s", collection, id, resp.StatusCode, body)
	}
	return nil
}
