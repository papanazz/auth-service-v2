package token

import (
	"time"

	"github.com/google/uuid"
)

type Claims struct {

	// Subject identity.
	UserID uuid.UUID

	// Authentication session.
	//
	// Allows access token invalidation
	// through session revocation.
	SessionID uuid.UUID
}

type AccessToken struct {

	// Serialized access token.
	//
	// Example:
	// JWT string
	Token string

	// Token issue time.
	IssuedAt time.Time

	// Token expiration.
	ExpiresAt time.Time
}
