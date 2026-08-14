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

	// DeviceGracePeriod bounds how a login is treated when the same device
	// already holds an active session: within this window of that session's
	// creation, the new login supersedes it; past it, the new login is
	// rejected. See LoginDeviceConfig for the full rationale.
	DeviceGracePeriod time.Duration
}
