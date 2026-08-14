package verification

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Cache holds a token's raw value for a window matching its own TTL, so
// a resend requested while the token is still valid can re-publish the
// exact same link instead of minting a new one and leaving the first
// email pointing at a dead token.
//
// This is the one deliberate exception to "raw tokens are never
// persisted" (see Token.Hash) — bounded to the token's own validity
// window, backed by Redis rather than Postgres, and never durable. A
// cache miss is not an error: the caller's correct response is to fall
// back to minting a fresh token, not to fail the request.
type Cache interface {
	StoreRawToken(
		ctx context.Context,
		tokenID uuid.UUID,
		rawToken string,
		ttl time.Duration,
	) error

	// GetRawToken returns the cached raw value and true if present.
	// ("", false, nil) means a clean miss — expired, evicted, or never
	// cached — not a failure.
	GetRawToken(
		ctx context.Context,
		tokenID uuid.UUID,
	) (
		string,
		bool,
		error,
	)
}
