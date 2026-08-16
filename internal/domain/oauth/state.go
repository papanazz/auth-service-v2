package oauth

import (
	"context"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/session"
)

// StatePayload is everything oauthstart needs to hand oauthcallback that
// Google's own redirect can't carry back for it. Google's callback only
// ever appends ?code=...&state=... — any client-supplied context (which
// device this login is for) has to survive the round trip some other
// way, so it travels bound to state instead.
type StatePayload struct {
	CodeVerifier string

	DeviceID string

	DeviceName string

	DeviceType session.DeviceType
}

// StateStore is the single-use claim behind the state parameter — CSRF
// protection for the callback, and the carrier for StatePayload. Mirrors
// platform/idempotency's claim pattern: written once with a short TTL,
// consumed exactly once, gone either way.
type StateStore interface {
	Store(
		ctx context.Context,
		state string,
		payload StatePayload,
		ttl time.Duration,
	) error

	// Consume atomically retrieves and deletes the record for state.
	// found is false for an unknown, expired, or already-consumed
	// state — the caller cannot and must not distinguish those from
	// each other; all three mean "this callback is not going to
	// proceed."
	Consume(
		ctx context.Context,
		state string,
	) (
		payload StatePayload,
		found bool,
		err error,
	)
}
