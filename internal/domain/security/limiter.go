package security

import "context"

type Limiter interface {
	Check(
		ctx context.Context,
		key string,
		policy LimitPolicy,
	) Decision

	Reset(
		ctx context.Context,
		key string,
	) error
}
