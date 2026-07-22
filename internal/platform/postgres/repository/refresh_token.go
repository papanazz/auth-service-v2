package repository

import (
	"context"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

type RefreshTokenRepository struct {
	tokenTTL int
	query    *sqlc.Queries
}

func NewRefreshTokenRepository(
	tokenTTL int,
	query *sqlc.Queries,
) *RefreshTokenRepository {

	return &RefreshTokenRepository{
		tokenTTL: tokenTTL,
		query:    query,
	}
}

func (r *RefreshTokenRepository) Create(
	ctx context.Context,
	t refresh_token.Token,
) error {

	_, err :=
		r.query.CreateRefreshToken(
			ctx,
			sqlc.CreateRefreshTokenParams{
				ID:        t.ID,
				SessionID: t.SessionID,
				TokenHash: t.Hash,
				ExpiresAt: time.Now().Add(time.Duration(r.tokenTTL) * time.Second),
			},
		)

	return err
}
