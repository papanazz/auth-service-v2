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

	if err :=
		s.passwords.Verify(
			account.PasswordHash,
			cmd.Password,
		); err != nil {

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

	_ =
		s.attemptTracker.Reset(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
		)

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

		_ =
			s.audit.Publish(
				ctx,
				loginFailedEvent(
					&account.ID,
					email,
					cmd.IPAddress,
					cmd.UserAgent,
					errs.ErrAccountLocked.Message,
				),
			)

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

			_ =
				s.audit.Publish(
					ctx,
					loginFailedEvent(
						&account.ID,
						email,
						cmd.IPAddress,
						cmd.UserAgent,
						errs.ErrDeviceSessionActive.Message,
					),
				)
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

	_ =
		s.audit.Publish(
			ctx,
			loginSuccessEvent(
				account.ID,
				sessionID,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		)

	_ =
		s.users.UpdateLastLoginAt(
			ctx,
			account.ID,
		)

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

	_ =
		s.attemptTracker.RecordFailure(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
			s.policy.Credential,
		)

	_ =
		s.audit.Publish(
			ctx,
			loginFailedEvent(
				userID,
				email,
				cmd.IPAddress,
				cmd.UserAgent,
				reason,
			),
		)
}
