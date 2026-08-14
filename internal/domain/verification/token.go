package verification

import (
	"time"

	"github.com/google/uuid"
)

// Token proves control of the email address on a user account.
//
// Unlike refresh_token.Token, there is no family/rotation/replay
// concept: a token authorizes exactly one thing (marking an email
// verified), consumed once, and multiple simultaneously-valid tokens
// for the same user are harmless — they all confirm the same mailbox.
type Token struct {
	ID uuid.UUID

	UserID uuid.UUID

	// Hashed token. Raw tokens are never persisted — see Cache for the
	// short-lived exception that makes resending the same link possible.
	Hash string

	ExpiresAt time.Time

	// Timestamp when this token was exchanged for a verified email.
	// A consumed token must never be reused.
	ConsumedAt *time.Time

	CreatedAt time.Time
}

func (t Token) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

func (t Token) Consumed() bool {
	return t.ConsumedAt != nil
}
