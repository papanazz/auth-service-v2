package security

import "time"

func LoginAttemptPolicy() LimitPolicy {

	return LimitPolicy{

		Type: PolicyLoginAttempt,

		Limit: 5,

		Window: 15 * time.Minute,
	}
}

func RefreshTokenPolicy() LimitPolicy {

	return LimitPolicy{

		Type: PolicyRefreshToken,

		Limit: 10,

		Window: time.Minute,
	}
}
