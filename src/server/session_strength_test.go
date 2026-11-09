package server

import (
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// A result whose evidence was weaker than the method's best case (a
// document-chip-zk passport without Active Authentication) records its own
// strength, so a policy's minimum strength sees 70, not 80.
func TestRecordMethodResultUsesResultStrength(t *testing.T) {
	s := NewInMemorySessionStore(time.Hour)
	now := time.Now()
	sess, err := s.Create(nil, now)
	if err != nil {
		t.Fatal(err)
	}
	md := types.MethodMetadata{ID: "document-chip-zk", Type: types.MethodTypeAnchor, Strength: 80}
	res := types.MethodResult{Success: true, MethodID: md.ID, VerifiedAt: now, AttestationDigest: "d", Strength: 70}
	if err := s.RecordMethodResult(sess.ID, res, md); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.VerifiedMethods) != 1 || got.VerifiedMethods[0].Strength != 70 {
		t.Fatalf("verified methods %+v", got.VerifiedMethods)
	}
	// Re-running the ceremony with Active Authentication replaces it at 80.
	res.Strength = 80
	if err := s.RecordMethodResult(sess.ID, res, md); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(sess.ID)
	if got.VerifiedMethods[0].Strength != 80 {
		t.Fatalf("after AA: %+v", got.VerifiedMethods)
	}
}
