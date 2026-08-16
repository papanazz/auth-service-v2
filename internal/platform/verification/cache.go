package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	domain "github.com/papanazz/auth-service-v2/internal/domain/verification"
)

var _ domain.Cache = (*RedisCache)(nil)

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(
	client *redis.Client,
) *RedisCache {

	return &RedisCache{
		client: client,
	}
}

func (c *RedisCache) StoreRawToken(
	ctx context.Context,
	tokenID uuid.UUID,
	rawToken string,
	ttl time.Duration,
) error {

	if err := c.client.Set(
		ctx,
		key(tokenID),
		rawToken,
		ttl,
	).Err(); err != nil {

		return fmt.Errorf("store verification token in cache: %w", err)
	}

	return nil
}

func (c *RedisCache) GetRawToken(
	ctx context.Context,
	tokenID uuid.UUID,
) (
	string,
	bool,
	error,
) {

	value, err :=
		c.client.Get(
			ctx,
			key(tokenID),
		).Result()

	if err != nil {

		if errors.Is(
			err,
			redis.Nil,
		) {

			return "", false, nil
		}

		return "", false, fmt.Errorf("get verification token from cache: %w", err)
	}

	return value, true, nil
}

// key is prefixed so a token ID can never collide with an unrelated key
// pattern in this Redis instance (e.g. authattempt's or idempotency's).
func key(
	tokenID uuid.UUID,
) string {

	return "verify:token:" + tokenID.String()
}
