package refresh

import (
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func validateToken(
	token *refresh_token.Token,
) error {

	now :=
		time.Now()

	if token.RevokedAt != nil {

		return errs.ErrInvalidRefreshToken
	}

	if token.ExpiresAt.Before(now) {

		return errs.ErrInvalidRefreshToken
	}

	if token.ConsumedAt != nil {

		return errs.ErrRefreshTokenReplay
	}

	return nil
}
