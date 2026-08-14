package authattempt

import (
	"context"
	"errors"
	"strings"

	"github.com/redis/go-redis/v9"

	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	"github.com/papanazz/auth-service-v2/internal/domain/security"
	"github.com/papanazz/auth-service-v2/internal/platform/metrics"
)

var _ auth.AttemptTracker = (*RedisTracker)(nil)

type RedisTracker struct {
	client *redis.Client

	script *redis.Script

	metrics *metrics.Metrics
}

func NewRedisTracker(
	client *redis.Client,
	m *metrics.Metrics,
) *RedisTracker {

	return &RedisTracker{

		client: client,

		script: redis.NewScript(
			incrementScript,
		),

		metrics: m,
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

	allowed := count < policy.Limit

	if !allowed {

		r.metrics.RateLimitRejectionsTotal.
			WithLabelValues(
				limiterFromKey(key),
			).
			Inc()
	}

	return allowed, nil
}

// limiterFromKey classifies a rate-limit key for the RateLimitRejectionsTotal
// label without ever exposing the identifying suffix (an IP address or a
// credential hash) that makes each key unique — that suffix is exactly
// what a Prometheus label must never carry, since it would turn a handful
// of bounded time series into one per caller. Every key produced by this
// package (see key.go) has the shape "auth:<endpoint>:<limiter>:<value>";
// this keeps the first three segments and drops the rest.
func limiterFromKey(
	key string,
) string {

	parts := strings.SplitN(key, ":", 4)

	if len(parts) < 3 {
		return "unknown"
	}

	return strings.Join(parts[:3], ":")
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
