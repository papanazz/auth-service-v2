package session

import (
	"context"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

type Repository interface {
	Create(ctx context.Context, session Session) error
	//Revoke(ctx context.Context,id uuid.UUID) error

	WithTx(sqlc.DBTX) Repository
}
