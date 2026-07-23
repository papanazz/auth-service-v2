package auth

import (
	"context"

	"github.com/papanazz/auth-service-v2/internal/domain/security"
)

type AttemptTracker interface {
	Check(
		ctx context.Context,
		key string,
		policy security.LimitPolicy,
	) (bool, error)

	RecordFailure(
		ctx context.Context,
		key string,
		policy security.LimitPolicy,
	) error

	Reset(
		ctx context.Context,
		key string,
	) error
}
