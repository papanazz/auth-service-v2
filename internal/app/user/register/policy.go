package register

import (
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/security"
)

type SecurityPolicy struct {
	IP security.LimitPolicy

	// EmailVerificationTokenTTL bounds how long the token issued at
	// registration stays valid, and is the TTL used for its raw-value
	// cache entry too — see domain/verification.Cache.
	EmailVerificationTokenTTL time.Duration
}
