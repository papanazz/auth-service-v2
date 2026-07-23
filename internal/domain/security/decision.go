package security

import "time"

type Decision struct {
	Allowed bool

	Reason string

	RetryAfter *time.Duration

	EvaluatedAt time.Time
}

func Allow() Decision {

	return Decision{

		Allowed: true,

		EvaluatedAt: time.Now().UTC(),
	}
}

func Deny(
	reason string,
	retryAfter time.Duration,
) Decision {

	return Decision{

		Allowed: false,

		Reason: reason,

		RetryAfter: &retryAfter,

		EvaluatedAt: time.Now().UTC(),
	}
}
