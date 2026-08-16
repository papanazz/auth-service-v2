package authattempt

import (
	"context"
	"errors"
	"fmt"
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

		return false, fmt.Errorf("check rate limit count: %w", err)
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

	if err != nil {
		return fmt.Errorf("record auth attempt failure: %w", err)
	}

	return nil
}

func (r *RedisTracker) Reset(
	ctx context.Context,
	key string,
) error {

	err := r.client.Del(
		ctx,
		key,
	).Err()

	if err != nil {
		return fmt.Errorf("reset rate limit counter: %w", err)
	}

	return nil
}

func (r *RedisTracker) increment(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) (
	int,
	error,
) {

	count, err :=
		r.script.Run(
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

	if err != nil {
		return 0, fmt.Errorf("run rate limit increment script: %w", err)
	}

	return count, nil
}
