package refresh_token

import (
	"time"

	"github.com/google/uuid"
)

type Token struct {
	ID uuid.UUID

	SessionID uuid.UUID

	Hash string

	ExpiresAt time.Time

	RevokedAt *time.Time

	UsedAt *time.Time

	CreatedAt time.Time
}
