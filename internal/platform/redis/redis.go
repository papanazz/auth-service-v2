package redis

import (
	"context"

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

	if err := redisotel.InstrumentTracing(client); err != nil {
		return nil, err
	}

	if err := redisotel.InstrumentMetrics(client); err != nil {
		return nil, err
	}

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
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
	return r.Client.Ping(ctx).Err()
}
