package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TransactionManager struct {
	pool *pgxpool.Pool
}

func NewTransactionManager(
	pool *pgxpool.Pool,
) *TransactionManager {

	return &TransactionManager{
		pool: pool,
	}
}

func (m *TransactionManager) WithinTransaction(
	ctx context.Context,
	fn func(tx pgx.Tx) error,
) error {

	txCtx, cancel :=
		context.WithTimeout(
			ctx,
			3*time.Second,
		)

	defer cancel()

	tx, err :=
		m.pool.BeginTx(
			txCtx,
			pgx.TxOptions{
				IsoLevel: pgx.ReadCommitted,
			},
		)

	if err != nil {
		return err
	}

	defer func() {

		_ = tx.Rollback(
			txCtx,
		)

	}()

	if err :=
		fn(tx); err != nil {

		return err
	}

	return tx.Commit(
		txCtx,
	)
}
