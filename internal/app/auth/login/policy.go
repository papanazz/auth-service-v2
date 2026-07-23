package login

import (
	"github.com/papanazz/auth-service-v2/internal/domain/security"
)

type SecurityPolicy struct {
	IP security.LimitPolicy

	Credential security.LimitPolicy
}
