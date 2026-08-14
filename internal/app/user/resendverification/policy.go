package resendverification

import (
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/security"
)

type SecurityPolicy struct {
	IP security.LimitPolicy

	// TokenTTL bounds how long a newly minted token stays valid, and is
	// the TTL used for its raw-value cache entry too — see
	// domain/verification.Cache.
	TokenTTL time.Duration
}
