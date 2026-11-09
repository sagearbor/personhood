package server

// Holder revocation: revoke a PERSON, not just one credential.
//
// POST /v1/admin/revoke takes a credential id. That is not enough when a
// person is caught cheating: they may hold several credentials, and they
// can enrol again on the same inbox, phone or face and get a fresh one.
// Holder revocation (Config.HolderRevocation, env HOLDER_REVOCATION_ENABLED)
// closes both gaps:
//
//   - At issuance the issuer records, per holder DID, each credential id and
//     the credential's nullifierBinding commitment (HolderLedger).
//   - Revoking a holder bans the holder DID, revokes every credential it was
//     issued, and bans every nullifier commitment those credentials carried.
//     The commitment is a pure function of the nullifier seed (the email or
//     phone seed, the biometric commitment, or the holder key), so banning
//     it bans the seed: a later enrollment that resolves to the same seed is
//     refused with nullifier_revoked, whatever new device key it brings.
//   - The people who vouched for the holder are penalized
//     (socialvouching.InPerson.Penalize), when in-person vouching is on.
//
// Two ways in:
//
//   - POST /v1/revocations/equivocation: public. The body is a
//     credential.EquivocationProof, two conflicting slot statements signed
//     by one holder key (OpenLine's instant-payment double spend). The proof
//     verifies itself, so no token is needed: only the key's owner (or
//     someone who stole the key) can produce it.
//   - POST /v1/admin/revoke-holder: the operator's bearer token, for
//     duplicates found by other means.
//
// Both are idempotent. Credentials issued before the flag was on have no
// ledger record, so revoking their holder bans the DID (and the holder-key
// nullifier) but cannot find their credential ids or seed-derived
// nullifiers; revoke those with /v1/admin/revoke.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
	"github.com/sagearbor/personhood/pkg/redisclient"
	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
)

// Ban kinds.
const (
	BanKindHolder    = "holder"
	BanKindNullifier = "nullifier"
	// BanKindPardon marks an equivocation proof (by its canonical digest)
	// that an operator reviewed and found honest, such as a double-sign
	// caused by a wallet bug. Re-submitting that proof does not ban again.
	BanKindPardon = "pardon"
)

// IssuanceRecord is what the ledger keeps per issued credential.
type IssuanceRecord struct {
	CredentialID string `json:"credential_id"`
	// NullifierCommitments are the commitments of every nullifier seed the
	// session touched: the credential's own binding, the holder-key
	// binding, and an email/phone seed that a biometric binding overrode.
	NullifierCommitments []string  `json:"nullifier_commitments,omitempty"`
	IssuedAt             time.Time `json:"issued_at"`
}

// BanRecord explains a ban, for audit.
type BanRecord struct {
	Reason string `json:"reason"`
	// EvidenceDigest is hex SHA-256 of the evidence (the equivocation
	// proof's JSON), empty for an operator's ban.
	EvidenceDigest string    `json:"evidence_digest,omitempty"`
	At             time.Time `json:"at"`
}

// HolderLedger records issuances per holder and banned holders/nullifiers.
// Implementations MUST be safe for concurrent use; Ban MUST be create-only.
type HolderLedger interface {
	RecordIssuance(ctx context.Context, holder types.DID, rec IssuanceRecord) error
	Issuances(ctx context.Context, holder types.DID) ([]IssuanceRecord, error)
	// Ban records value under kind. already is true when it was banned
	// before; the first record is kept.
	Ban(ctx context.Context, kind, value string, rec BanRecord) (already bool, err error)
	Banned(ctx context.Context, kind, value string) (bool, error)
	// BanInfo returns the record of a ban, if there is one.
	BanInfo(ctx context.Context, kind, value string) (BanRecord, bool, error)
	// Unban removes a ban (an operator's reinstatement after review).
	// Removing a ban that does not exist is not an error.
	Unban(ctx context.Context, kind, value string) error
}

// NewHolderLedgerFromEnv picks Firestore, then Redis, then memory, like the
// other stores. An in-memory ledger forgets bans on restart.
func NewHolderLedgerFromEnv() (HolderLedger, error) {
	if projectID := os.Getenv("FIRESTORE_PROJECT_ID"); projectID != "" {
		client, err := firestoreclient.New(projectID)
		if err != nil {
			return nil, fmt.Errorf("server: FIRESTORE_PROJECT_ID: %w", err)
		}
		return newKVHolderLedger(firestoreKV{client}), nil
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		client, err := redisclient.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("server: REDIS_URL: %w", err)
		}
		return newKVHolderLedger(redisKV{client}), nil
	}
	return NewInMemoryHolderLedger(), nil
}

// ----------------------------------------------------------------------------
// In-memory
// ----------------------------------------------------------------------------

// InMemoryHolderLedger keeps everything in process memory. Dev and tests.
type InMemoryHolderLedger struct {
	mu        sync.Mutex
	issuances map[types.DID][]IssuanceRecord
	bans      map[string]BanRecord // kind + "\x00" + value
}

func NewInMemoryHolderLedger() *InMemoryHolderLedger {
	return &InMemoryHolderLedger{issuances: map[types.DID][]IssuanceRecord{}, bans: map[string]BanRecord{}}
}

func (l *InMemoryHolderLedger) RecordIssuance(_ context.Context, holder types.DID, rec IssuanceRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.issuances[holder] = append(l.issuances[holder], rec)
	return nil
}

func (l *InMemoryHolderLedger) Issuances(_ context.Context, holder types.DID) ([]IssuanceRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]IssuanceRecord(nil), l.issuances[holder]...), nil
}

func (l *InMemoryHolderLedger) Ban(_ context.Context, kind, value string, rec BanRecord) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := kind + "\x00" + value
	if _, ok := l.bans[k]; ok {
		return true, nil
	}
	l.bans[k] = rec
	return false, nil
}

func (l *InMemoryHolderLedger) Banned(_ context.Context, kind, value string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.bans[kind+"\x00"+value]
	return ok, nil
}

func (l *InMemoryHolderLedger) BanInfo(_ context.Context, kind, value string) (BanRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.bans[kind+"\x00"+value]
	return rec, ok, nil
}

func (l *InMemoryHolderLedger) Unban(_ context.Context, kind, value string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.bans, kind+"\x00"+value)
	return nil
}

// ----------------------------------------------------------------------------
// Firestore / Redis, through one small key-value shape
// ----------------------------------------------------------------------------

// kv is the subset of Firestore and Redis the ledger needs.
type kv interface {
	get(ctx context.Context, ns, id string) ([]byte, bool, error)
	set(ctx context.Context, ns, id string, b []byte) error
	create(ctx context.Context, ns, id string, b []byte) (bool, error)
	del(ctx context.Context, ns, id string) error
}

type firestoreKV struct{ c *firestoreclient.Client }

func (f firestoreKV) get(ctx context.Context, ns, id string) ([]byte, bool, error) {
	return f.c.Get(ctx, ns, id)
}
func (f firestoreKV) set(ctx context.Context, ns, id string, b []byte) error {
	return f.c.Set(ctx, ns, id, b, 0)
}
func (f firestoreKV) create(ctx context.Context, ns, id string, b []byte) (bool, error) {
	return f.c.Create(ctx, ns, id, b)
}
func (f firestoreKV) del(ctx context.Context, ns, id string) error {
	return f.c.Del(ctx, ns, id)
}

type redisKV struct{ c *redisclient.Client }

func (r redisKV) key(ns, id string) string { return "personhood:" + ns + ":" + id }
func (r redisKV) get(ctx context.Context, ns, id string) ([]byte, bool, error) {
	return r.c.Get(ctx, r.key(ns, id))
}
func (r redisKV) set(ctx context.Context, ns, id string, b []byte) error {
	return r.c.Set(ctx, r.key(ns, id), b, 0)
}
func (r redisKV) create(ctx context.Context, ns, id string, b []byte) (bool, error) {
	return redisSetNX(ctx, r.c, r.key(ns, id), b)
}
func (r redisKV) del(ctx context.Context, ns, id string) error {
	return r.c.Del(ctx, r.key(ns, id))
}

// memKV is the in-memory kv, for dev and tests.
type memKV struct {
	mu   sync.Mutex
	docs map[string][]byte
}

func newMemKV() *memKV { return &memKV{docs: map[string][]byte{}} }

func (m *memKV) get(_ context.Context, ns, id string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.docs[ns+"\x00"+id]
	return append([]byte(nil), b...), ok, nil
}
func (m *memKV) set(_ context.Context, ns, id string, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.docs[ns+"\x00"+id] = append([]byte(nil), b...)
	return nil
}
func (m *memKV) create(_ context.Context, ns, id string, b []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[ns+"\x00"+id]; ok {
		return false, nil
	}
	m.docs[ns+"\x00"+id] = append([]byte(nil), b...)
	return true, nil
}
func (m *memKV) del(_ context.Context, ns, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.docs, ns+"\x00"+id)
	return nil
}

// newKVFromEnv picks Firestore, then Redis, then memory, like every store.
func newKVFromEnv() (kv, error) {
	if projectID := os.Getenv("FIRESTORE_PROJECT_ID"); projectID != "" {
		client, err := firestoreclient.New(projectID)
		if err != nil {
			return nil, fmt.Errorf("server: FIRESTORE_PROJECT_ID: %w", err)
		}
		return firestoreKV{client}, nil
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		client, err := redisclient.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("server: REDIS_URL: %w", err)
		}
		return redisKV{client}, nil
	}
	return newMemKV(), nil
}

const (
	kvIssuancesNS = "personhood-holder-issuances"
	kvBansNS      = "personhood-bans"
)

// kvHolderLedger stores one document per holder (id = sha256(holder DID))
// holding its issuance list, and one create-only document per ban (id =
// kind-sha256(value)). RecordIssuance is a read-modify-write under a
// process mutex: safe while the issuer runs as one instance, like
// FirestoreRevocationStore.Revoke.
type kvHolderLedger struct {
	kv kv
	mu sync.Mutex
}

func newKVHolderLedger(k kv) *kvHolderLedger { return &kvHolderLedger{kv: k} }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type issuanceDoc struct {
	Records []IssuanceRecord `json:"records"`
}

func (l *kvHolderLedger) RecordIssuance(ctx context.Context, holder types.DID, rec IssuanceRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	recs, err := l.issuances(ctx, holder)
	if err != nil {
		return err
	}
	b, err := json.Marshal(issuanceDoc{Records: append(recs, rec)})
	if err != nil {
		return err
	}
	return l.kv.set(ctx, kvIssuancesNS, sha256Hex(string(holder)), b)
}

func (l *kvHolderLedger) Issuances(ctx context.Context, holder types.DID) ([]IssuanceRecord, error) {
	return l.issuances(ctx, holder)
}

func (l *kvHolderLedger) issuances(ctx context.Context, holder types.DID) ([]IssuanceRecord, error) {
	raw, found, err := l.kv.get(ctx, kvIssuancesNS, sha256Hex(string(holder)))
	if err != nil || !found {
		return nil, err
	}
	var doc issuanceDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("server: corrupt issuance record: %w", err)
	}
	return doc.Records, nil
}

func (l *kvHolderLedger) Ban(ctx context.Context, kind, value string, rec BanRecord) (bool, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return false, err
	}
	created, err := l.kv.create(ctx, kvBansNS, kind+"-"+sha256Hex(value), b)
	return !created, err
}

func (l *kvHolderLedger) Banned(ctx context.Context, kind, value string) (bool, error) {
	_, found, err := l.kv.get(ctx, kvBansNS, kind+"-"+sha256Hex(value))
	return found, err
}

func (l *kvHolderLedger) BanInfo(ctx context.Context, kind, value string) (BanRecord, bool, error) {
	raw, found, err := l.kv.get(ctx, kvBansNS, kind+"-"+sha256Hex(value))
	if err != nil || !found {
		return BanRecord{}, false, err
	}
	var rec BanRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return BanRecord{}, false, fmt.Errorf("server: corrupt ban record: %w", err)
	}
	return rec, true, nil
}

func (l *kvHolderLedger) Unban(ctx context.Context, kind, value string) error {
	return l.kv.del(ctx, kvBansNS, kind+"-"+sha256Hex(value))
}

// ----------------------------------------------------------------------------
// The cascade
// ----------------------------------------------------------------------------

// holderRevocationReport is the response of both revoke-holder endpoints.
type holderRevocationReport struct {
	HolderDID types.DID `json:"holder_did"`
	// AlreadyBanned is true when this holder had been revoked before.
	AlreadyBanned bool `json:"already_banned"`
	// KnownHolder is false when the ledger has no credential for this DID.
	KnownHolder        bool `json:"known_holder"`
	RevokedCredentials int  `json:"revoked_credentials"`
	NullifiersBanned   int  `json:"nullifiers_banned"`
	VouchersPenalized  int  `json:"vouchers_penalized"`
}

// revokeHolder bans holder and everything issued to it. The holder ban is
// written first, so a failure part-way still blocks re-enrollment; calling
// again finishes the job.
func (s *Server) revokeHolder(ctx context.Context, holder types.DID, rec BanRecord) (holderRevocationReport, error) {
	rep := holderRevocationReport{HolderDID: holder}
	already, err := s.holders.Ban(ctx, BanKindHolder, string(holder), rec)
	if err != nil {
		return rep, fmt.Errorf("ban holder: %w", err)
	}
	rep.AlreadyBanned = already

	// The holder-key nullifier is a function of the DID's key, so it is
	// banned even when the ledger has no record of this holder.
	nullifiers := map[string]bool{}
	if pub, err := Ed25519FromDIDKey(holder); err == nil {
		nullifiers[NullifierBindingForHolder(pub).Commitment] = true
	}
	recs, err := s.holders.Issuances(ctx, holder)
	if err != nil {
		return rep, fmt.Errorf("read issuances: %w", err)
	}
	rep.KnownHolder = len(recs) > 0
	for _, r := range recs {
		_, alreadyRevoked, err := s.revocations.Revoke(ctx, r.CredentialID)
		switch {
		case errors.Is(err, ErrCredentialNotFound):
		case err != nil:
			return rep, fmt.Errorf("revoke credential: %w", err)
		case !alreadyRevoked:
			rep.RevokedCredentials++
		}
		for _, c := range r.NullifierCommitments {
			nullifiers[c] = true
		}
	}
	for c := range nullifiers {
		was, err := s.holders.Ban(ctx, BanKindNullifier, c, rec)
		if err != nil {
			return rep, fmt.Errorf("ban nullifier: %w", err)
		}
		if !was {
			rep.NullifiersBanned++
		}
	}
	if s.inPerson != nil {
		pen, err := s.inPerson.Penalize(ctx, string(holder))
		if err != nil {
			return rep, err
		}
		rep.VouchersPenalized = len(pen.Vouchers)
	}
	return rep, nil
}

// sessionNullifierCommitments lists the commitment of every nullifier seed
// view touched: nb (the credential's binding), the holder-key binding, and,
// when a biometric binding won (bioWon), the email/phone seed it overrode.
func (s *Server) sessionNullifierCommitments(ctx context.Context, view SessionView, nb *types.NullifierBinding, bioWon bool) ([]string, error) {
	var out []string
	add := func(b *types.NullifierBinding) {
		if b == nil {
			return
		}
		for _, c := range out {
			if c == b.Commitment {
				return
			}
		}
		out = append(out, b.Commitment)
	}
	add(nb)
	add(NullifierBindingForHolder(view.HolderPublicKey))
	if bioWon && s.identifierKeys != nil && len(view.IdentifierKeys) > 0 {
		seed, err := resolveIdentifierSeed(ctx, s.identifiers, view.IdentifierKeys)
		if err != nil {
			return nil, err
		}
		add(NullifierBindingForIdentifierSeed(seed))
	}
	return out, nil
}

// checkHolderBans refuses issuance to a revoked holder or onto a banned
// nullifier seed.
func (s *Server) checkHolderBans(ctx context.Context, holder types.DID, commitments []string) (*apiError, error) {
	banned, err := s.holders.Banned(ctx, BanKindHolder, string(holder))
	if err != nil {
		return nil, err
	}
	if banned {
		return &apiError{"holder_revoked", "this holder key was revoked and cannot be issued a credential. " + appealHint}, nil
	}
	for _, c := range commitments {
		banned, err = s.holders.Banned(ctx, BanKindNullifier, c)
		if err != nil {
			return nil, err
		}
		if banned {
			return &apiError{"nullifier_revoked", "the identity behind this enrollment was revoked and cannot enrol again. " + appealHint}, nil
		}
	}
	return nil, nil
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

// handleEquivocation is POST /v1/revocations/equivocation.
func (s *Server) handleEquivocation(w http.ResponseWriter, r *http.Request) {
	var proof credential.EquivocationProof
	if err := decodeJSON(r, &proof); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	pub, err := proof.Verify()
	if err != nil {
		writeError(w, http.StatusBadRequest, "proof_invalid", err.Error())
		return
	}
	holder, err := DIDKeyFromEd25519(pub)
	if err != nil {
		writeError(w, http.StatusBadRequest, "proof_invalid", err.Error())
		return
	}
	digest := equivocationDigest(pub, proof)
	pardoned, err := s.holders.Banned(r.Context(), BanKindPardon, digest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	if pardoned {
		writeError(w, http.StatusConflict, "evidence_pardoned",
			"an operator reviewed this exact proof and reinstated the holder; it does not revoke them again")
		return
	}
	rep, err := s.revokeHolder(r.Context(), holder, BanRecord{
		Reason:         "equivocation: " + proof.Context,
		EvidenceDigest: digest,
		At:             s.nowFunc(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// equivocationDigest is a canonical digest of an equivocation proof: the
// key, context and slot plus the two payload digests in sorted order, so
// the same double-sign hashes the same however its JSON is spelled or its
// statements are ordered. It is the ban's EvidenceDigest, and the key a
// pardon is recorded under.
func equivocationDigest(pub ed25519.PublicKey, p credential.EquivocationProof) string {
	a, b := p.Statements[0].PayloadDigestHex, p.Statements[1].PayloadDigestHex
	if b < a {
		a, b = b, a
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{"personhood-equivocation-evidence/v1", hex.EncodeToString(pub), p.Context, p.Slot, a, b}, "\n")))
	return hex.EncodeToString(sum[:])
}

// appealHint is appended to every refusal caused by a ban, so an honest
// person who was banned by mistake knows the way back.
const appealHint = "If you think this is a mistake, appeal with POST /v1/appeals (where the issuer accepts appeals) or contact the issuer's operator."

type adminRevokeHolderRequest struct {
	HolderDID string `json:"holder_did"`
	Reason    string `json:"reason"`
}

// handleAdminRevokeHolder is POST /v1/admin/revoke-holder.
func (s *Server) handleAdminRevokeHolder(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid admin bearer token is required")
		return
	}
	var req adminRevokeHolderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.HolderDID, req.Reason = strings.TrimSpace(req.HolderDID), strings.TrimSpace(req.Reason)
	if !strings.HasPrefix(req.HolderDID, "did:") || req.Reason == "" || len(req.Reason) > 200 {
		writeError(w, http.StatusBadRequest, "invalid_request", "holder_did (a DID) and reason (1..200 characters) are required")
		return
	}
	rep, err := s.revokeHolder(r.Context(), types.DID(req.HolderDID), BanRecord{Reason: "operator: " + req.Reason, At: s.nowFunc()})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
