package session

import (
	"context"

	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

type Repository interface {
	Create(
		ctx context.Context,
		session Session,
	) error

	FindByID(
		ctx context.Context,
		id uuid.UUID,
	) (
		*Session,
		error,
	)

	FindActiveByID(
		ctx context.Context,
		id uuid.UUID,
	) (
		*Session,
		error,
	)

	FindActiveByUserAndDevice(
		ctx context.Context,
		userID uuid.UUID,
		deviceID string,
	) (
		*Session,
		error,
	)

	Revoke(
		ctx context.Context,
		id uuid.UUID,
		reason RevokeReason,
	) error

	UpdateLastUsedAt(
		ctx context.Context,
		id uuid.UUID,
	) error

	UpdateLastRefreshedAt(
		ctx context.Context,
		id uuid.UUID,
	) error

	WithTx(
		tx sqlc.DBTX,
	) Repository
}
