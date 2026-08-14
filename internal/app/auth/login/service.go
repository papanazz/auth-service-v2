package login

import (
	"context"
	"errors"
	"strings"
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

	email :=
		strings.ToLower(
			strings.TrimSpace(
				cmd.Email,
			),
		)

	if err :=
		Validate(
			email,
			cmd.Password,
		); err != nil {

		return nil, err
	}

	//
	// 1. Rate limit check
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
	// 2. Find account
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
	// 3. Verify password
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

	//
	// 4. Authentication success
	//

	_ =
		s.attemptTracker.Reset(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
		)

	//
	// A device may hold at most one active session (uq_sessions_active_device).
	// A second login for the same device within the grace period is treated as
	// the same client retrying — e.g. after a network timeout that lost the
	// first response — so the stale session is superseded rather than left to
	// collide with the new one. Past the grace period the existing session is
	// left alone and the login is rejected: silently killing a session that has
	// been active for a while looks more like a bug or an attacker than a retry.
	//

	existingSession, err :=
		s.sessions.FindActiveByUserAndDevice(
			ctx,
			account.ID,
			cmd.DeviceID,
		)

	if err != nil && !errors.Is(err, errs.ErrSessionNotFound) {

		return nil, err
	}

	var supersedes *uuid.UUID

	if existingSession != nil {

		if time.Since(existingSession.CreatedAt) > s.policy.DeviceGracePeriod {

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

			return nil,
				errs.ErrDeviceSessionActive
		}

		supersedes = &existingSession.ID
	}

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
	// 5. Persist authentication state
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

				if supersedes != nil {

					err :=
						txSessionRepo.Revoke(
							ctx,
							*supersedes,
							session.RevokeSessionSuperseded,
						)

					if err != nil {

						return err
					}
				}

				err :=
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

		return nil, err
	}

	//
	// 6. Publish audit event
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
