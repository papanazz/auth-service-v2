package verification

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/papanazz/auth-service-v2/internal/domain/verification"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var _ verification.Repository = (*VerificationRepository)(nil)

type VerificationRepository struct {
	query *sqlc.Queries
}

func NewVerificationRepository(
	query *sqlc.Queries,
) *VerificationRepository {

	return &VerificationRepository{
		query: query,
	}
}

func (r *VerificationRepository) WithTx(
	tx pgx.Tx,
) verification.Repository {

	return &VerificationRepository{
		query: sqlc.New(tx),
	}
}

func (r *VerificationRepository) Create(
	ctx context.Context,
	token verification.Token,
) error {

	_, err :=
		r.query.CreateVerificationToken(
			ctx,
			sqlc.CreateVerificationTokenParams{

				ID: token.ID,

				UserID: token.UserID,

				TokenHash: token.Hash,

				ExpiresAt: pgtype.Timestamptz{

					Time: token.ExpiresAt,

					Valid: true,
				},
			},
		)

	return err
}

func (r *VerificationRepository) FindByHash(
	ctx context.Context,
	hash string,
) (
	*verification.Token,
	error,
) {

	row, err :=
		r.query.GetVerificationTokenByHash(
			ctx,
			hash,
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrVerificationTokenNotFound
		}

		return nil, err
	}

	return mapToken(row), nil
}

func (r *VerificationRepository) FindActiveByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (
	*verification.Token,
	error,
) {

	row, err :=
		r.query.GetActiveVerificationTokenByUserID(
			ctx,
			userID,
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrVerificationTokenNotFound
		}

		return nil, err
	}

	return mapToken(row), nil
}

func (r *VerificationRepository) Consume(
	ctx context.Context,
	id uuid.UUID,
) (
	bool,
	error,
) {

	rows, err :=
		r.query.ConsumeVerificationToken(
			ctx,
			id,
		)

	if err != nil {
		return false, err
	}

	return rows == 1, nil
}

func mapToken(
	row sqlc.EmailVerificationToken,
) *verification.Token {

	result := &verification.Token{

		ID: row.ID,

		UserID: row.UserID,

		Hash: row.TokenHash,

		ExpiresAt: row.ExpiresAt.Time,

		CreatedAt: row.CreatedAt.Time,
	}

	if row.ConsumedAt.Valid {

		t := row.ConsumedAt.Time

		result.ConsumedAt = &t
	}

	return result
}
