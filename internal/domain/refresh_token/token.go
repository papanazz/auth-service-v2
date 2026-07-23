package refresh_token

import (
	"time"

	"github.com/google/uuid"
)

type Token struct {
	ID uuid.UUID

	SessionID uuid.UUID

	// Represents one refresh token rotation chain.
	//
	// Example:
	//
	// Token A
	//    |
	// Token B
	//    |
	// Token C
	//
	FamilyID uuid.UUID

	// Previous token in rotation chain.
	//
	// NULL means this is the first token
	// created during login.
	//
	ParentTokenID *uuid.UUID

	// Hashed refresh token.
	//
	// Raw refresh tokens are never persisted.
	//
	Hash string

	// Maximum lifetime of this refresh token.
	//
	ExpiresAt time.Time

	// Timestamp when token was successfully exchanged.
	//
	// A consumed token must never be reused.
	//
	ConsumedAt *time.Time

	// Token invalidation timestamp.
	//
	RevokedAt *time.Time

	// Why this token was revoked.
	//
	RevokedReason *RevokeReason

	CreatedAt time.Time
}
