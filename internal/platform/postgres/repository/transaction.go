package repository

import (
	"context"
	"fmt"
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
		return fmt.Errorf("begin transaction: %w", err)
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

	// fn's error is returned completely untouched — never wrapped. It
	// may be a raw infra failure from one of its own repository calls
	// (already wrapped there, if so), or it may be a domain sentinel a
	// service deliberately returns from inside its own transaction
	// closure (e.g. login's errs.ErrDeviceSessionActive). The transport
	// layer type-asserts on *errs.Error (response.WriteError) rather
	// than using errors.As — wrapping here would silently turn every
	// such sentinel into a 500, since a wrapped error is no longer of
	// that concrete type even though errors.Is/As would still find it.
	// This function has no way to tell which case it's looking at, so
	// the only correct choice is to pass it through exactly as received.
	if err :=
		fn(tx); err != nil {

		return err
	}

	if err :=
		tx.Commit(txCtx); err != nil {

		return fmt.Errorf("commit transaction: %w", err)
	}

	committed = true

	return nil
}
