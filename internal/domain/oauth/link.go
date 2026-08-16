package oauth

import (
	"time"

	"github.com/google/uuid"
)

// Link is a persisted, confirmed association between one account and
// one third-party identity — the durable record of an account-linking
// decision already made, unlike Identity, which is just what a code
// exchange happened to return.
type Link struct {
	ID uuid.UUID

	UserID uuid.UUID

	Provider Provider

	ProviderUserID string

	Email string

	CreatedAt time.Time
}
