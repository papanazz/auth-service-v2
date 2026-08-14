package user

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Repository interface {
	FindByID(
		ctx context.Context,
		id uuid.UUID,
	) (
		*User,
		error,
	)

	FindByEmail(
		ctx context.Context,
		email string,
	) (
		*User,
		error,
	)

	Create(
		ctx context.Context,
		user User,
	) error

	// MarkEmailVerified persists the result of User.VerifyEmail().
	//
	// status is passed in rather than recomputed here: the PENDING ->
	// ACTIVE transition is a domain rule (VerifyEmail), and this method
	// just persists whatever the caller already decided.
	MarkEmailVerified(
		ctx context.Context,
		userID uuid.UUID,
		verifiedAt time.Time,
		status Status,
	) error

	// UpdateLastLoginAt records a successful authentication. Called
	// best-effort, after login's own transaction has committed — not
	// critical enough to hold up or fail a login that already succeeded.
	UpdateLastLoginAt(
		ctx context.Context,
		userID uuid.UUID,
	) error

	// Transaction support: verifying an email atomically consumes its
	// token and marks the user verified.
	WithTx(
		tx pgx.Tx,
	) Repository
}
