package token

import (
	"time"

	"github.com/google/uuid"
)

type Claims struct {
	UserID uuid.UUID
}

type AccessToken struct {
	Token string

	ExpiresAt time.Time
}

type AccessTokenService interface {
	Generate(
		claims Claims,
	) (
		AccessToken,
		error,
	)
}
