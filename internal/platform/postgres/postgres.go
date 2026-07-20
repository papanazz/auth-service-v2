package postgres

import (
	"context"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
)

func New(
	ctx context.Context,
	cfg config.DatabaseConfig,
) (*pgxpool.Pool, error) {

	poolConfig, err := pgxpool.ParseConfig(cfg.URL)

	if err != nil {
		return nil, err
	}

	poolConfig.MaxConns = cfg.MaxConnections
	poolConfig.MinConns = cfg.MinConnections
	poolConfig.MaxConnLifetime = cfg.MaxConnectionLifetime
	poolConfig.MaxConnIdleTime = cfg.MaxConnectionIdleTime
	poolConfig.HealthCheckPeriod = cfg.HealthCheckPeriod

	poolConfig.ConnConfig.Tracer = otelpgx.NewTracer()

	pool, err := pgxpool.NewWithConfig(
		ctx,
		poolConfig,
	)

	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}
