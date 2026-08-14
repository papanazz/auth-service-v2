package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var _ user.Repository = (*UserRepository)(nil)

type UserRepository struct {
	query *sqlc.Queries
}

func NewUserRepository(
	query *sqlc.Queries,
) *UserRepository {

	return &UserRepository{
		query: query,
	}

}

func (r *UserRepository) Create(
	ctx context.Context,
	account user.User,
) error {

	_, err :=
		r.query.CreateUser(
			ctx,
			sqlc.CreateUserParams{

				ID: account.ID,

				Email: account.Email,

				PasswordHash: account.PasswordHash,

				Status: sqlc.UserStatus(
					account.Status,
				),

				EmailVerifiedAt: account.EmailVerifiedAt,
			},
		)

	return err
}

func (r *UserRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (
	*user.User,
	error,
) {

	row, err :=
		r.query.GetUserByID(
			ctx,
			id,
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrUserNotFound
		}

		return nil, err
	}

	return mapUser(row), nil

}

func (r *UserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (
	*user.User,
	error,
) {

	row, err :=
		r.query.GetUserByEmail(
			ctx,
			email,
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrUserNotFound
		}

		return nil, err

	}

	return mapUser(row), nil

}

func (r *UserRepository) MarkEmailVerified(
	ctx context.Context,
	userID uuid.UUID,
	verifiedAt time.Time,
	status user.Status,
) error {

	return r.query.MarkEmailVerified(
		ctx,
		sqlc.MarkEmailVerifiedParams{

			ID: userID,

			EmailVerifiedAt: &verifiedAt,

			Status: sqlc.UserStatus(
				status,
			),
		},
	)
}

func (r *UserRepository) UpdateLastLoginAt(
	ctx context.Context,
	userID uuid.UUID,
) error {

	return r.query.UpdateLastLoginAt(
		ctx,
		userID,
	)
}

func (r *UserRepository) WithTx(
	tx pgx.Tx,
) user.Repository {

	return &UserRepository{
		query: sqlc.New(tx),
	}
}

func mapUser(
	row sqlc.User,
) *user.User {

	return &user.User{

		ID: row.ID,

		Email: row.Email,

		PasswordHash: row.PasswordHash,

		Status: user.Status(
			row.Status,
		),

		EmailVerifiedAt: row.EmailVerifiedAt,

		LastLoginAt: row.LastLoginAt,

		CreatedAt: row.CreatedAt,

		UpdatedAt: row.UpdatedAt,
	}

}
