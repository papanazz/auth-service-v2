package login

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/papanazz/auth-service-v2/internal/app/auth/sessionissuer"
	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	"github.com/papanazz/auth-service-v2/internal/domain/logging"
	"github.com/papanazz/auth-service-v2/internal/domain/password"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
)

type Command struct {
	Email string

	Password string

	DeviceID string

	DeviceName string

	DeviceType session.DeviceType

	IPAddress string

	UserAgent string
}

type Result struct {
	AccessToken string `json:"access_token"`

	RefreshToken string `json:"refresh_token"`

	ExpiresIn int64 `json:"expires_in"`
}

type LoginService struct {
	users user.Repository

	passwords password.Verifier

	issuer *sessionissuer.Issuer

	audit audit.Publisher

	attemptTracker auth.AttemptTracker

	logger logging.Logger

	policy SecurityPolicy
}

func NewService(
	users user.Repository,
	passwords password.Verifier,
	issuer *sessionissuer.Issuer,
	audit audit.Publisher,
	attemptTracker auth.AttemptTracker,
	logger logging.Logger,
	policy SecurityPolicy,
) *LoginService {

	return &LoginService{

		users: users,

		passwords: passwords,

		issuer: issuer,

		audit: audit,

		attemptTracker: attemptTracker,

		logger: logger,

		policy: policy,
	}
}

func (s *LoginService) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

	//
	// 1. Normalize and validate input
	//

	email :=
		user.NormalizeEmail(
			cmd.Email,
		)

	if err :=
		Validate(
			email,
			cmd.Password,
			cmd.DeviceID,
			cmd.DeviceType,
		); err != nil {

		return nil, err
	}

	//
	// 2. Rate limit check
	//

	allowed, err :=
		s.attemptTracker.Check(
			ctx,
			authattempt.LoginIP(
				cmd.IPAddress,
			),
			s.policy.IP,
		)

	if err != nil {
		return nil, err
	}

	if !allowed {

		return nil,
			errs.ErrTooManyRequests
	}

	allowed, err =
		s.attemptTracker.Check(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
			s.policy.Credential,
		)

	if err != nil {
		return nil, err
	}

	if !allowed {

		return nil,
			errs.ErrTooManyRequests
	}

	//
	// 3. Find account
	//

	account, err :=
		s.users.FindByEmail(
			ctx,
			email,
		)

	if err != nil {

		// A genuine lookup failure (Postgres unreachable, a timeout, ...)
		// is not "unknown account" — conflating the two used to mean an
		// infra outage silently returned 401 INVALID_CREDENTIALS to
		// every caller instead of 500, and logged at Warn instead of
		// Error, hiding a real incident inside routine login-failure
		// noise. Only ErrUserNotFound gets the enumeration-safe
		// treatment below; anything else propagates as-is.
		if !errors.Is(err, errs.ErrUserNotFound) {
			return nil, err
		}

		//
		// Important:
		// Run dummy Argon2 verification
		// to prevent user enumeration
		//

		_ =
			s.passwords.Verify(
				dummyPasswordHash,
				cmd.Password,
			)

		s.recordFailure(
			ctx,
			nil,
			email,
			cmd,
			errs.ErrInvalidCredentials.Message,
		)

		return nil,
			errs.ErrInvalidCredentials
	}

	//
	// 4. Verify password
	//
	// An OAuth-only account (docs/oauth.md) has no password at all —
	// PasswordHash is nil. That must fail exactly like a wrong password,
	// not panic on a nil dereference and not reveal "this account has
	// no password": both would hand out account-existence/shape
	// information for free, the same enumeration-safety stance already
	// applied to an unknown account above.
	//

	if account.PasswordHash == nil {

		_ =
			s.passwords.Verify(
				dummyPasswordHash,
				cmd.Password,
			)

		_ =
			s.attemptTracker.RecordFailure(
				ctx,
				authattempt.LoginCredential(
					email,
					cmd.IPAddress,
				),
				s.policy.Credential,
			)

		s.recordFailure(
			ctx,
			&account.ID,
			email,
			cmd,
			errs.ErrInvalidCredentials.Message,
		)

		return nil,
			errs.ErrInvalidCredentials
	}

	if err :=
		s.passwords.Verify(
			*account.PasswordHash,
			cmd.Password,
		); err != nil {

		if err :=
			s.attemptTracker.RecordFailure(
				ctx,
				authattempt.LoginCredential(
					email,
					cmd.IPAddress,
				),
				s.policy.Credential,
			); err != nil {

			s.logger.Error(ctx, "[Login] credential rate limit counter increment failed", err, nil)
		}

		s.recordFailure(
			ctx,
			&account.ID,
			email,
			cmd,
			errs.ErrInvalidCredentials.Message,
		)

		return nil,
			errs.ErrInvalidCredentials
	}

	if err :=
		s.attemptTracker.Reset(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
		); err != nil {

		// Not fatal — the counter merely fails to clear, so a legitimate
		// user could see a stale credential-limit warning sooner than
		// deserved on a subsequent attempt. Worth knowing about, not
		// worth failing an otherwise-successful login over.
		s.logger.Error(ctx, "[Login] credential rate limit counter reset failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	//
	// 5. Account status check
	//
	// Deliberately after password verification, not before: revealing
	// "this account is locked" to a caller who has not yet proven they
	// know the password would hand out account-existence information for
	// free. This does not count against the credential rate limiter — the
	// password was correct, so treating it as a guessing failure would let
	// anyone who already knows a locked account's password lock out its
	// legitimate owner by hammering this path.
	//

	if !account.CanLogin(time.Now()) {

		if err :=
			s.audit.Publish(
				ctx,
				loginFailedEvent(
					&account.ID,
					email,
					cmd.IPAddress,
					cmd.UserAgent,
					errs.ErrAccountLocked.Message,
				),
			); err != nil {

			s.logger.Error(ctx, "[Login] audit publish failed", err, map[string]any{
				"user_id": account.ID,
			})
		}

		return nil,
			errs.ErrAccountLocked
	}

	//
	// 6. Issue the session, refresh token, and access token
	//
	// Delegated to sessionissuer.Issuer — the exact transactional logic
	// (device-slot locking, supersede-within-grace-period, session +
	// refresh token creation) that used to live inline here, extracted
	// so oauthcallback can mint sessions the identical way instead of
	// reimplementing it. See docs/oauth.md.
	//

	issued, err :=
		s.issuer.IssueForDevice(
			ctx,
			account.ID,
			cmd.DeviceID,
			cmd.DeviceName,
			cmd.DeviceType,
			cmd.IPAddress,
			cmd.UserAgent,
		)

	if err != nil {

		if errors.Is(err, errs.ErrDeviceSessionActive) {

			if auditErr :=
				s.audit.Publish(
					ctx,
					loginFailedEvent(
						&account.ID,
						email,
						cmd.IPAddress,
						cmd.UserAgent,
						errs.ErrDeviceSessionActive.Message,
					),
				); auditErr != nil {

				s.logger.Error(ctx, "[Login] audit publish failed", auditErr, map[string]any{
					"user_id": account.ID,
				})
			}
		}

		return nil, err
	}

	//
	// 7. Publish audit event and record the last login timestamp
	//
	// Both best-effort, both after the transaction commits: neither is
	// critical enough to fail a login that already succeeded, and
	// last_login_at is explicitly documented (queries/user.sql) as not
	// belonging inside the transaction that creates the session/token.
	//

	if err :=
		s.audit.Publish(
			ctx,
			loginSuccessEvent(
				account.ID,
				issued.SessionID,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[Login] audit publish failed", err, map[string]any{
			"user_id": account.ID,

			"session_id": issued.SessionID,
		})
	}

	if err :=
		s.users.UpdateLastLoginAt(
			ctx,
			account.ID,
		); err != nil {

		s.logger.Error(ctx, "[Login] update last login at failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	return &Result{

		AccessToken: issued.AccessToken,

		RefreshToken: issued.RefreshToken,

		ExpiresIn: issued.ExpiresIn,
	}, nil
}

func (s *LoginService) recordFailure(
	ctx context.Context,
	userID *uuid.UUID,
	email string,
	cmd Command,
	reason string,
) {

	if err :=
		s.attemptTracker.RecordFailure(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
			s.policy.Credential,
		); err != nil {

		s.logger.Error(ctx, "[Login] credential rate limit counter increment failed", err, nil)
	}

	if err :=
		s.audit.Publish(
			ctx,
			loginFailedEvent(
				userID,
				email,
				cmd.IPAddress,
				cmd.UserAgent,
				reason,
			),
		); err != nil {

		s.logger.Error(ctx, "[Login] audit publish failed", err, nil)
	}
}
