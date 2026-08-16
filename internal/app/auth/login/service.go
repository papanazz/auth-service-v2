package login

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	"github.com/papanazz/auth-service-v2/internal/domain/logging"
	"github.com/papanazz/auth-service-v2/internal/domain/password"
	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
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
	transaction transaction.Manager

	users user.Repository

	sessions session.Repository

	refreshTokens refresh_token.Repository

	passwords password.Verifier

	accessTokens token.AccessTokenService

	refreshGenerator refresh_token.Generator

	refreshHasher refresh_token.Hasher

	audit audit.Publisher

	attemptTracker auth.AttemptTracker

	logger logging.Logger

	policy SecurityPolicy
}

func NewService(
	transaction transaction.Manager,
	users user.Repository,
	sessions session.Repository,
	refreshTokens refresh_token.Repository,
	passwords password.Verifier,
	accessTokens token.AccessTokenService,
	refreshGenerator refresh_token.Generator,
	refreshHasher refresh_token.Hasher,
	audit audit.Publisher,
	attemptTracker auth.AttemptTracker,
	logger logging.Logger,
	policy SecurityPolicy,
) *LoginService {

	return &LoginService{

		transaction: transaction,

		users: users,

		sessions: sessions,

		refreshTokens: refreshTokens,

		passwords: passwords,

		accessTokens: accessTokens,

		refreshGenerator: refreshGenerator,

		refreshHasher: refreshHasher,

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
	// 6. Authentication success
	//

	sessionID :=
		uuid.New()

	familyID :=
		uuid.New()

	//
	// Generate refresh token
	//

	rawRefreshToken, err :=
		s.refreshGenerator.Generate()

	if err != nil {

		return nil, err
	}

	//
	// Generate access token
	//
	// No database dependency
	//

	accessToken, err :=
		s.accessTokens.Generate(
			token.Claims{

				UserID: account.ID,

				SessionID: sessionID,
			},
		)

	if err != nil {

		return nil, err
	}

	//
	// 7. Persist authentication state
	//

	err =
		s.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				now := time.Now().UTC()

				txSessionRepo :=
					s.sessions.WithTx(
						tx,
					)

				//
				// A device may hold at most one active session
				// (uq_sessions_active_device). The lock below serializes
				// concurrent logins for this device so the read that follows
				// cannot go stale before this transaction acts on it — without
				// it, two concurrent retries could both see the same existing
				// session as supersede-able and race each other into the
				// unique constraint.
				//
				// A second login for the same device within the grace period
				// is treated as the same client retrying — e.g. after a
				// network timeout that lost the first response — so the
				// stale session is superseded rather than left to collide
				// with the new one. Past the grace period the existing
				// session is left alone and the login is rejected: silently
				// killing a session that has been active for a while looks
				// more like a bug or an attacker than a retry.
				//

				if err :=
					txSessionRepo.LockDeviceSlot(
						ctx,
						account.ID,
						cmd.DeviceID,
					); err != nil {

					return err
				}

				existingSession, err :=
					txSessionRepo.FindActiveByUserAndDevice(
						ctx,
						account.ID,
						cmd.DeviceID,
					)

				if err != nil && !errors.Is(err, errs.ErrSessionNotFound) {

					return err
				}

				if existingSession != nil {

					if time.Since(existingSession.CreatedAt) > s.policy.DeviceGracePeriod {

						return errs.ErrDeviceSessionActive
					}

					if err :=
						txSessionRepo.Revoke(
							ctx,
							existingSession.ID,
							session.RevokeSessionSuperseded,
						); err != nil {

						return err
					}
				}

				err =
					txSessionRepo.Create(
						ctx,
						session.Session{

							ID: sessionID,

							UserID: account.ID,

							DeviceID: cmd.DeviceID,

							DeviceName: cmd.DeviceName,

							DeviceType: cmd.DeviceType,

							IPAddress: cmd.IPAddress,

							UserAgent: cmd.UserAgent,

							LastUsedAt: &now,

							ExpiresAt: now.
								Add(
									s.policy.SessionTTL,
								).
								UTC(),

							CreatedAt: now.UTC(),
						},
					)

				if err != nil {

					return err
				}

				txRefreshRepo :=
					s.refreshTokens.WithTx(
						tx,
					)

				return txRefreshRepo.Create(
					ctx,
					refresh_token.Token{

						ID: uuid.New(),

						SessionID: sessionID,

						FamilyID: familyID,

						ParentTokenID: nil,

						Hash: s.refreshHasher.Hash(
							rawRefreshToken,
						),

						ExpiresAt: time.Now().
							Add(
								s.policy.RefreshTokenTTL,
							).
							UTC(),

						CreatedAt: time.Now().UTC(),
					},
				)
			},
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
	// 8. Publish audit event and record the last login timestamp
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
				sessionID,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[Login] audit publish failed", err, map[string]any{
			"user_id": account.ID,

			"session_id": sessionID,
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

		AccessToken: accessToken.Token,

		RefreshToken: rawRefreshToken,

		ExpiresIn: int64(
			time.Until(
				accessToken.ExpiresAt,
			).Seconds(),
		),
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
