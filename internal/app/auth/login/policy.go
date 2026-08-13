package login

import (
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/security"
)

type SecurityPolicy struct {
	IP security.LimitPolicy

	Credential security.LimitPolicy

	RefreshTokenTTL time.Duration

	// SessionTTL must be >= RefreshTokenTTL. A refresh token is only accepted
	// while its session is still active, so a shorter session TTL would reject
	// tokens that have not expired yet.
	SessionTTL time.Duration
}
