package security

import "time"

type PolicyType string

const (
	PolicyLoginAttempt PolicyType = "LOGIN_ATTEMPT"

	PolicyRefreshToken PolicyType = "REFRESH_TOKEN"

	PolicyAPIRateLimit PolicyType = "API_RATE_LIMIT"

	PolicyRegisterAttempt PolicyType = "REGISTER_ATTEMPT"

	PolicyResendVerification PolicyType = "RESEND_VERIFICATION"
)

type LimitPolicy struct {
	Type PolicyType

	// Maximum allowed attempts
	// within the time window.
	Limit int

	// Sliding/fixed window duration.
	Window time.Duration
}
