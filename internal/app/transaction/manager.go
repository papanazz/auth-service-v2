package transaction

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Manager controls application transaction boundaries.
//
// Use cases should define transaction scope.
// Repositories receive the transaction through WithTx().
type Manager interface {
	WithinTransaction(
		ctx context.Context,
		fn func(tx pgx.Tx) error,
	) error
}
