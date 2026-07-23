package repository

import (
	"context"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

type RefreshTokenRepository struct {
	tokenTTL time.Duration
	query    *sqlc.Queries
}

func NewRefreshTokenRepository(
	tokenTTL time.Duration,
	query *sqlc.Queries,
) *RefreshTokenRepository {

	return &RefreshTokenRepository{
		tokenTTL: tokenTTL,
		query:    query,
	}
}

func (r *RefreshTokenRepository) WithTx(
	tx sqlc.DBTX,
) refresh_token.Repository {

	return &RefreshTokenRepository{
		tokenTTL: r.tokenTTL,
		query:    sqlc.New(tx),
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
				ExpiresAt: time.Now().Add(r.tokenTTL),
			},
		)

	return err
}
