package oauthidentity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	domain "github.com/papanazz/auth-service-v2/internal/domain/oauth"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	query *sqlc.Queries
}

func NewRepository(
	query *sqlc.Queries,
) *Repository {

	return &Repository{
		query: query,
	}
}

func (r *Repository) FindByProviderID(
	ctx context.Context,
	provider domain.Provider,
	providerUserID string,
) (
	*domain.Link,
	error,
) {

	row, err :=
		r.query.GetOAuthIdentityByProviderID(
			ctx,
			sqlc.GetOAuthIdentityByProviderIDParams{

				Provider: string(provider),

				ProviderUserID: providerUserID,
			},
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrOAuthIdentityNotFound
		}

		return nil, fmt.Errorf("get oauth identity by provider id: %w", err)
	}

	return &domain.Link{

		ID: row.ID,

		UserID: row.UserID,

		Provider: domain.Provider(row.Provider),

		ProviderUserID: row.ProviderUserID,

		Email: row.Email,

		CreatedAt: row.CreatedAt.Time,
	}, nil
}

func (r *Repository) Create(
	ctx context.Context,
	link domain.Link,
) error {

	_, err :=
		r.query.CreateOAuthIdentity(
			ctx,
			sqlc.CreateOAuthIdentityParams{

				ID: link.ID,

				UserID: link.UserID,

				Provider: string(link.Provider),

				ProviderUserID: link.ProviderUserID,

				Email: link.Email,
			},
		)

	if err != nil {
		return fmt.Errorf("create oauth identity: %w", err)
	}

	return nil
}

func (r *Repository) WithTx(
	tx pgx.Tx,
) domain.Repository {

	return &Repository{
		query: sqlc.New(tx),
	}
}
