package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TransactionManager struct {
	pool *pgxpool.Pool

	timeout time.Duration
}

func NewTransactionManager(
	pool *pgxpool.Pool,
	timeout time.Duration,
) *TransactionManager {

	return &TransactionManager{

		pool: pool,

		timeout: timeout,
	}
}

func (m *TransactionManager) WithinTransaction(
	ctx context.Context,
	fn func(tx pgx.Tx) error,
) error {

	txCtx, cancel :=
		context.WithTimeout(
			ctx,
			m.timeout,
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

	committed := false

	defer func() {

		if !committed {

			rollbackCtx, cancel :=
				context.WithTimeout(
					context.Background(),
					time.Second,
				)

			defer cancel()

			_ = tx.Rollback(
				rollbackCtx,
			)
		}

	}()

	if err :=
		fn(tx); err != nil {

		return err
	}

	if err :=
		tx.Commit(txCtx); err != nil {

		return err
	}

	committed = true

	return nil
}
