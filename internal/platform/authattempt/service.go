package authattempt

import (
	"context"
	"errors"

	"github.com/redis/go-redis/v9"

	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	"github.com/papanazz/auth-service-v2/internal/domain/security"
)

var _ auth.AttemptTracker = (*RedisTracker)(nil)

type RedisTracker struct {
	client *redis.Client

	script *redis.Script
}

func NewRedisTracker(
	client *redis.Client,
) *RedisTracker {

	return &RedisTracker{

		client: client,

		script: redis.NewScript(
			incrementScript,
		),
	}
}

func (r *RedisTracker) Check(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) (bool, error) {

	count, err :=
		r.client.Get(
			ctx,
			key,
		).Int()

	if err != nil {

		if errors.Is(
			err,
			redis.Nil,
		) {
			return true, nil
		}

		return false, err
	}

	return count < policy.Limit, nil
}

func (r *RedisTracker) RecordFailure(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) error {

	_, err :=
		r.increment(
			ctx,
			key,
			policy,
		)

	return err
}

func (r *RedisTracker) Reset(
	ctx context.Context,
	key string,
) error {

	return r.client.Del(
		ctx,
		key,
	).Err()

}

func (r *RedisTracker) increment(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) (
	int,
	error,
) {

	return r.script.Run(
		ctx,
		r.client,
		[]string{
			key,
		},
		int(
			policy.Window.Seconds(),
		),
	).
		Int()

}
