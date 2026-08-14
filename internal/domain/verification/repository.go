package verification

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Repository interface {

	// Create persists a newly issued token.
	Create(
		ctx context.Context,
		token Token,
	) error

	// FindByHash looks up a token by its SHA256 hash during the verify
	// flow.
	FindByHash(
		ctx context.Context,
		hash string,
	) (
		*Token,
		error,
	)

	// FindActiveByUserID returns the most recent unconsumed, unexpired
	// token for a user, if any. Used by resend to decide whether to
	// reuse it instead of minting a new one.
	FindActiveByUserID(
		ctx context.Context,
		userID uuid.UUID,
	) (
		*Token,
		error,
	)

	// Consume marks a token exchanged.
	//
	// Conditional UPDATE (consumed_at IS NULL), so concurrent verify
	// calls for the same token can only have one winner. Returns false
	// when already consumed.
	Consume(
		ctx context.Context,
		id uuid.UUID,
	) (
		bool,
		error,
	)

	// Transaction support: verifying atomically consumes the token and
	// marks the user's email verified.
	WithTx(
		tx pgx.Tx,
	) Repository
}
