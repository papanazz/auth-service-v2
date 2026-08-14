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

	// LockDeviceSlot serializes concurrent logins for the same (user, device)
	// pair for the lifetime of the current transaction, so a decide-then-act
	// sequence built around FindActiveByUserAndDevice cannot race a concurrent
	// login for the same device into the uq_sessions_active_device constraint.
	// Must be called inside a transaction; the lock releases automatically
	// when that transaction ends.
	LockDeviceSlot(
		ctx context.Context,
		userID uuid.UUID,
		deviceID string,
	) error

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
