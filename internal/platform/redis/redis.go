package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"

	"github.com/papanazz/auth-service-v2/internal/platform/config"
)

type Cache struct {
	Client *redis.Client
}

func New(
	ctx context.Context,
	cfg config.RedisConfig,
) (*Cache, error) {

	client := redis.NewClient(
		&redis.Options{
			Addr: cfg.Address,

			Password: cfg.Password,

			DB: cfg.DB,

			PoolSize: cfg.PoolSize,

			MinIdleConns: cfg.MinIdleConnections,

			DialTimeout: cfg.DialTimeout,

			ReadTimeout: cfg.ReadTimeout,

			WriteTimeout: cfg.WriteTimeout,

			PoolTimeout: cfg.PoolTimeout,

			ConnMaxIdleTime: cfg.IdleTimeout,
		},
	)

	// WithDBStatement(false): the tracing hook's default captures every
	// command *argument*, not just the command name — for this client
	// that means the raw email-verification token
	// (platform/verification.RedisCache.StoreRawToken) and the raw
	// access+refresh token pair cached for idempotent login replay
	// (platform/idempotency.Store.Save) would otherwise appear verbatim
	// in every trace shipped to Jaeger. Postgres's tracer
	// (platform/postgres.New) is safe by default here — otelpgx only
	// captures SQL bind values if WithIncludeQueryParameters is passed,
	// which this codebase never does — so Redis needed the same
	// treatment explicitly. See docs/tracing.md.
	if err := redisotel.InstrumentTracing(client, redisotel.WithDBStatement(false)); err != nil {
		return nil, fmt.Errorf("instrument redis tracing: %w", err)
	}

	if err := redisotel.InstrumentMetrics(client); err != nil {
		return nil, fmt.Errorf("instrument redis metrics: %w", err)
	}

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &Cache{
		Client: client,
	}, nil
}

func (r *Cache) Close() {
	_ = r.Client.Close()
}

func (r *Cache) Health(
	ctx context.Context,
) error {

	if err := r.Client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}

	return nil
}
