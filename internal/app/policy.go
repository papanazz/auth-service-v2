package app

import (
	"github.com/papanazz/auth-service-v2/internal/app/auth/login"
	"github.com/papanazz/auth-service-v2/internal/app/user/register"
	"github.com/papanazz/auth-service-v2/internal/app/user/resendverification"
	"github.com/papanazz/auth-service-v2/internal/domain/security"
	"github.com/papanazz/auth-service-v2/internal/platform/config"
)

// newLoginSecurityPolicy translates configuration into the login use case's
// security policy.
//
// This lives apart from New so it can be exercised without a database or Redis.
// Use-case tests construct SecurityPolicy directly, so a field left unwired
// here is invisible to them: the policy silently carries a zero value, and a
// zero duration means "already expired". That is exactly how refresh tokens
// once shipped expired at the moment of issue.
func newLoginSecurityPolicy(
	cfg *config.Config,
) login.SecurityPolicy {

	return login.SecurityPolicy{

		IP: security.LimitPolicy{

			Type: security.PolicyLoginAttempt,

			Limit: cfg.Security.Login.IP.Limit,

			Window: cfg.Security.Login.IP.Window,
		},

		Credential: security.LimitPolicy{

			Type: security.PolicyLoginAttempt,

			Limit: cfg.Security.Login.Email.Limit,

			Window: cfg.Security.Login.Email.Window,
		},

		RefreshTokenTTL: cfg.Security.RefreshToken.TTL,

		SessionTTL: cfg.Security.Session.TTL,

		DeviceGracePeriod: cfg.Security.Login.Device.GracePeriod,
	}
}

// newRegisterSecurityPolicy translates configuration into the register use
// case's security policy. Kept apart from New for the same reason
// newLoginSecurityPolicy is — see its comment.
func newRegisterSecurityPolicy(
	cfg *config.Config,
) register.SecurityPolicy {

	return register.SecurityPolicy{

		IP: security.LimitPolicy{

			Type: security.PolicyRegisterAttempt,

			Limit: cfg.Security.Register.IP.Limit,

			Window: cfg.Security.Register.IP.Window,
		},

		EmailVerificationTokenTTL: cfg.EmailVerification.TokenTTL,
	}
}

// newResendVerificationSecurityPolicy translates configuration into the
// resend-verification use case's security policy. Kept apart from New
// for the same reason newLoginSecurityPolicy is — see its comment.
func newResendVerificationSecurityPolicy(
	cfg *config.Config,
) resendverification.SecurityPolicy {

	return resendverification.SecurityPolicy{

		IP: security.LimitPolicy{

			Type: security.PolicyResendVerification,

			Limit: cfg.EmailVerification.Resend.Limit,

			Window: cfg.EmailVerification.Resend.Window,
		},

		TokenTTL: cfg.EmailVerification.TokenTTL,
	}
}
