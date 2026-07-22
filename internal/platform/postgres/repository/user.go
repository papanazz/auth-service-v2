package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

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
	u user.User,
) error {

	_, err :=
		r.query.CreateUser(
			ctx,
			sqlc.CreateUserParams{

				ID: u.ID,

				Email: u.Email,

				PasswordHash: u.PasswordHash,

				Status: sqlc.UserStatus(u.Status),
			},
		)

	return err
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.ErrUserNotFound
		}
		return nil, err

	}

	return &user.User{

		ID: row.ID,

		Email: row.Email,

		PasswordHash: row.PasswordHash,

		Status: user.Status(row.Status),
	}, nil

}
