package login

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	"github.com/papanazz/auth-service-v2/internal/domain/password"
	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	Email      string
	Password   string
	DeviceID   string
	DeviceName string
	DeviceType string
	IPAddress  string
	UserAgent  string
}

type Result struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type LoginService struct {
	transaction      transaction.Manager
	users            user.Repository
	sessions         session.Repository
	refreshTokens    refresh_token.Repository
	passwords        password.Repository
	audit            audit.Repository
	accessTokens     token.AccessTokenService
	refreshGenerator token.RefreshTokenGenerator
	hasher           token.Hasher
	attemptTracker   auth.AttemptTracker
	policy           SecurityPolicy
}

func NewService(
	transaction transaction.Manager,
	users user.Repository,
	sessions session.Repository,
	refreshTokens refresh_token.Repository,
	passwords password.Repository,
	audit audit.Repository,
	accessTokens token.AccessTokenService,
	refreshGenerator token.RefreshTokenGenerator,
	hasher token.Hasher,
	attemptTracker auth.AttemptTracker,
	policy SecurityPolicy,
) *LoginService {
	return &LoginService{
		transaction:      transaction,
		users:            users,
		sessions:         sessions,
		refreshTokens:    refreshTokens,
		passwords:        passwords,
		audit:            audit,
		accessTokens:     accessTokens,
		refreshGenerator: refreshGenerator,
		hasher:           hasher,
		attemptTracker:   attemptTracker,
		policy:           policy,
	}
}

func (h *LoginService) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

	// Normalize email

	email := strings.ToLower(
		strings.TrimSpace(cmd.Email),
	)

	// Check IP rate

	allowed, err :=
		h.attemptTracker.Check(
			ctx,
			authattempt.LoginIP(
				cmd.IPAddress,
			),
			h.policy.IP,
		)

	if err != nil {
		return nil, err
	}

	// Check Credential rate

	allowed, err =
		h.attemptTracker.Check(
			ctx,
			authattempt.LoginCredential(
				cmd.Email,
				cmd.IPAddress,
			),
			h.policy.Credential,
		)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, errs.ErrTooManyRequests
	}

	// Find user

	account, err :=
		h.users.FindByEmail(
			ctx,
			email,
		)

	if err != nil {

		_ = h.attemptTracker.RecordFailure(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
			h.policy.Credential,
		)

		_ = h.audit.Record(
			ctx,
			loginFailedEvent(
				nil,
				email,
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidCredentials.Message,
			),
		)

		return nil,
			errs.ErrInvalidCredentials
	}

	// Verify password

	err =
		h.passwords.Compare(
			account.PasswordHash,
			cmd.Password,
		)

	if err != nil {

		_ = h.attemptTracker.RecordFailure(
			ctx,
			authattempt.LoginCredential(
				email,
				cmd.IPAddress,
			),
			h.policy.Credential,
		)

		_ = h.audit.Record(
			ctx,
			loginFailedEvent(
				&account.ID,
				email,
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidCredentials.Message,
			),
		)

		return nil,
			errs.ErrInvalidCredentials
	}

	// Authentication success
	// Clear failed attempt counter

	_ = h.attemptTracker.Reset(
		ctx,
		authattempt.LoginCredential(
			email,
			cmd.IPAddress,
		),
	)

	// Generate refresh token
	// No database involved

	refreshToken, err :=
		h.refreshGenerator.Generate()

	if err != nil {
		return nil, err
	}

	// Database transaction

	err =
		h.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {
				sessionID := uuid.New()

				txSessionRepo :=
					h.sessions.WithTx(
						tx,
					)

				err :=
					txSessionRepo.Create(
						ctx,
						session.Session{
							ID:         sessionID,
							UserID:     account.ID,
							IpAddress:  cmd.IPAddress,
							UserAgent:  cmd.UserAgent,
							DeviceID:   cmd.DeviceID,
							DeviceName: cmd.DeviceName,
							DeviceType: session.DeviceType(cmd.DeviceType),
						},
					)

				if err != nil {
					return err
				}

				txRefreshRepo :=
					h.refreshTokens.WithTx(
						tx,
					)

				return txRefreshRepo.Create(
					ctx,
					refresh_token.Token{

						ID:        uuid.New(),
						SessionID: sessionID,
						Hash: h.hasher.Hash(
							refreshToken,
						),
					},
				)
			},
		)

	if err != nil {
		return nil, err
	}

	// Generate JWT
	// No DB transaction needed

	accessToken, err :=
		h.accessTokens.Generate(
			token.Claims{

				UserID: account.ID,
			},
		)

	if err != nil {
		return nil, err
	}

	// Audit success

	_ = h.audit.Record(
		ctx,
		loginSuccessEvent(
			account.ID,
			cmd.IPAddress,
			cmd.UserAgent,
		),
	)

	return &Result{
		AccessToken:  accessToken.Token,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(time.Until(accessToken.ExpiresAt).Seconds()),
	}, nil
}
