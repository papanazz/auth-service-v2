package login

import (
	"context"
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

				txSessionRepo :=
					s.sessions.WithTx(
						tx,
					)

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

							CreatedAt: time.Now().UTC(),
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
