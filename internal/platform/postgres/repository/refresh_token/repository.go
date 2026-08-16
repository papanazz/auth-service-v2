package refresh_token

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var _ refresh_token.Repository = (*RefreshTokenRepository)(nil)

type RefreshTokenRepository struct {
	query *sqlc.Queries
}

func NewRefreshTokenRepository(
	query *sqlc.Queries,
) *RefreshTokenRepository {

	return &RefreshTokenRepository{
		query: query,
	}
}

func (r *RefreshTokenRepository) WithTx(
	tx pgx.Tx,
) refresh_token.Repository {

	return &RefreshTokenRepository{
		query: sqlc.New(tx),
	}
}

func (r *RefreshTokenRepository) Create(
	ctx context.Context,
	input refresh_token.Token,
) error {

	_, err :=
		r.query.CreateRefreshToken(
			ctx,
			sqlc.CreateRefreshTokenParams{

				ID: input.ID,

				SessionID: input.SessionID,

				FamilyID: input.FamilyID,

				ParentTokenID: input.ParentTokenID,

				TokenHash: input.Hash,

				ExpiresAt: timeToPgTimestamp(
					input.ExpiresAt,
				),
			},
		)

	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	return nil
}

func (r *RefreshTokenRepository) FindByHash(
	ctx context.Context,
	hash string,
) (
	*refresh_token.Token,
	error,
) {

	row, err :=
		r.query.GetRefreshTokenByHash(
			ctx,
			hash,
		)

	if err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.ErrRefreshTokenNotFound
		}

		return nil, fmt.Errorf("get refresh token by hash: %w", err)
	}

	result := &refresh_token.Token{

		ID: row.ID,

		SessionID: row.SessionID,

		FamilyID: row.FamilyID,

		ParentTokenID: row.ParentTokenID,

		Hash: row.TokenHash,

		ExpiresAt: row.ExpiresAt.Time,

		CreatedAt: row.CreatedAt.Time,
	}

	if row.ConsumedAt.Valid {

		t := row.ConsumedAt.Time

		result.ConsumedAt = &t
	}

	if row.RevokedAt.Valid {

		t := row.RevokedAt.Time

		result.RevokedAt = &t
	}

	if row.RevokedReason.Valid {

		reason :=
			refresh_token.RevokeReason(
				row.RevokedReason.RefreshTokenRevokeReason,
			)

		result.RevokedReason = &reason
	}

	return result, nil
}

func (r *RefreshTokenRepository) Consume(
	ctx context.Context,
	id uuid.UUID,
) (
	bool,
	error,
) {

	rows, err :=
		r.query.ConsumeRefreshToken(
			ctx,
			id,
		)

	if err != nil {
		return false, fmt.Errorf("consume refresh token: %w", err)
	}

	return rows == 1, nil
}

func (r *RefreshTokenRepository) RevokeFamily(
	ctx context.Context,
	familyID uuid.UUID,
	reason refresh_token.RevokeReason,
) error {

	err := r.query.RevokeRefreshTokenFamily(
		ctx,
		sqlc.RevokeRefreshTokenFamilyParams{

			FamilyID: familyID,

			RevokedReason: sqlc.NullRefreshTokenRevokeReason{

				RefreshTokenRevokeReason: sqlc.RefreshTokenRevokeReason(reason),

				Valid: true,
			},
		},
	)

	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}

	return nil
}
