package refresh_token

import (
	"context"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

type Repository interface {
	Create(ctx context.Context, token Token) error
	//FindByHash(ctx context.Context, hash string) (*Token, error)
	//Revoke(ctx context.Context, id uuid.UUID) error

	WithTx(sqlc.DBTX) Repository
}
