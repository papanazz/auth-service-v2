package login

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/password"
	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
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
	users            user.Repository
	passwords        password.Repository
	sessions         session.Repository
	refreshTokens    refresh_token.Repository
	accessTokens     token.AccessTokenService
	refreshGenerator token.RefreshTokenGenerator
	hasher           token.Hasher
}

func NewService(
	users user.Repository,
	passwords password.Repository,
	sessions session.Repository,
	refreshTokens refresh_token.Repository,
	accessTokens token.AccessTokenService,
	refreshGenerator token.RefreshTokenGenerator,
	hasher token.Hasher,
) *LoginService {
	return &LoginService{
		users:            users,
		passwords:        passwords,
		sessions:         sessions,
		refreshTokens:    refreshTokens,
		accessTokens:     accessTokens,
		refreshGenerator: refreshGenerator,
		hasher:           hasher,
	}
}

func (h *LoginService) Handle(
	ctx context.Context,
	cmd Command,
) (
	*Result,
	error,
) {

	email := strings.ToLower(strings.TrimSpace(cmd.Email))

	if err := Validate(email, cmd.Password); err != nil {
		return nil, err
	}

	u, err := h.users.FindByEmail(ctx, email)

	if err != nil {
		return nil, errs.ErrInvalidCredentials
	}

	err = h.passwords.Compare(u.PasswordHash, cmd.Password)
	if err != nil {
		return nil, errs.ErrInvalidCredentials
	}

	sessionID := uuid.New()
	newSession := session.Session{
		ID:         sessionID,
		UserID:     u.ID,
		DeviceID:   cmd.DeviceID,
		DeviceName: cmd.DeviceName,
		DeviceType: session.DeviceType(cmd.DeviceType),
		UserAgent:  cmd.UserAgent,
		IpAddress:  cmd.IPAddress,
	}

	err = h.sessions.Create(ctx, newSession)
	if err != nil {
		return nil, err
	}

	refreshPlain, err := h.refreshGenerator.Generate()
	if err != nil {
		return nil, err
	}

	refresh := refresh_token.Token{
		ID:        uuid.New(),
		SessionID: sessionID,
		Hash: h.hasher.Hash(
			refreshPlain,
		),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	err = h.refreshTokens.Create(ctx, refresh)
	if err != nil {
		return nil, err
	}

	access, err := h.accessTokens.Generate(
		token.Claims{
			UserID: u.ID,
		},
	)

	if err != nil {
		return nil, err
	}

	return &Result{
		AccessToken:  access.Token,
		RefreshToken: refreshPlain,
		ExpiresIn:    int64(time.Until(access.ExpiresAt).Seconds()),
	}, nil
}
