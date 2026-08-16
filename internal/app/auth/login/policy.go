package login

import (
	"github.com/papanazz/auth-service-v2/internal/domain/security"
)

// RefreshTokenTTL, SessionTTL, and DeviceGracePeriod moved to
// sessionissuer.Policy when that package was extracted from this
// service — see docs/oauth.md.
type SecurityPolicy struct {
	IP security.LimitPolicy

	Credential security.LimitPolicy
}
