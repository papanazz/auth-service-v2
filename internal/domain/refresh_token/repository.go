package refresh_token

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Repository interface {

	// Find active refresh token by SHA256 hash.
	FindByHash(
		ctx context.Context,
		hash string,
	) (
		*Token,
		error,
	)

	// Create a new refresh token during:
	//
	// - login
	// - refresh rotation
	//
	Create(
		ctx context.Context,
		token Token,
	) error

	// Mark token as consumed.
	//
	// Used during refresh rotation.
	//
	// Returns false when:
	//
	// - token already consumed
	// - concurrent refresh happened
	//
	Consume(
		ctx context.Context,
		id uuid.UUID,
	) (
		bool,
		error,
	)

	// Revoke every token in a rotation family.
	//
	// Used for:
	//
	// - replay detection
	//
	RevokeFamily(
		ctx context.Context,
		familyID uuid.UUID,
		reason RevokeReason,
	) error

	// Transaction support.
	//
	// Needed because refresh rotation must be atomic:
	//
	// consume old token
	// create new token
	// update session
	//
	WithTx(
		tx pgx.Tx,
	) Repository
}
