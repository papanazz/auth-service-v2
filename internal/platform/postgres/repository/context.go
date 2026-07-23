package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type txKey struct{}

func TxFromContext(
	ctx context.Context,
) (pgx.Tx, bool) {

	tx, ok :=
		ctx.Value(
			txKey{},
		).(pgx.Tx)

	return tx, ok
}
