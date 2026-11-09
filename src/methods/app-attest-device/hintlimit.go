package appattestdevice

import (
	"context"
	"sync"
	"time"
)

// DeviceHintLimiter caps how many sessions may pass with the same
// Evidence.DeviceHint. It is a speed bump against one phone enrolling many
// identities, not a uniqueness check: the hint rotates (so a patient
// attacker waits), and a phone with no hint (older, factory-provisioned
// keys) is not limited at all.
type DeviceHintLimiter interface {
	// Allow records sessionID under hint and reports whether the hint is
	// still within its limit. Repeating a session already counted is
	// always allowed.
	Allow(ctx context.Context, hint, sessionID string) (bool, error)
}

// InMemoryHintLimiter allows up to Max distinct sessions per hint within
// Window. Single-process only: replicas each count separately.
type InMemoryHintLimiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	byHint map[string]map[string]time.Time // hint -> session -> first seen
}

// NewInMemoryHintLimiter builds a limiter. max must be >= 1; window <= 0
// means 30 days (longer than any RKP key lives).
func NewInMemoryHintLimiter(max int, window time.Duration) *InMemoryHintLimiter {
	if max < 1 {
		panic("app-attest-device.NewInMemoryHintLimiter: max must be >= 1")
	}
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	return &InMemoryHintLimiter{max: max, window: window, now: time.Now, byHint: map[string]map[string]time.Time{}}
}

// Allow implements DeviceHintLimiter.
func (l *InMemoryHintLimiter) Allow(_ context.Context, hint, sessionID string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	sessions := l.byHint[hint]
	if sessions == nil {
		sessions = map[string]time.Time{}
		l.byHint[hint] = sessions
	}
	for id, at := range sessions {
		if now.Sub(at) > l.window {
			delete(sessions, id)
		}
	}
	if _, seen := sessions[sessionID]; seen {
		return true, nil
	}
	if len(sessions) >= l.max {
		return false, nil
	}
	sessions[sessionID] = now
	return true, nil
}
