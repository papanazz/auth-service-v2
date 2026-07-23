package refresh

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	RefreshToken string
}

type Result struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type Service struct {
	transaction transaction.Manager

	refreshTokens refresh_token.Repository

	sessions session.Repository

	accessTokens token.AccessTokenService

	refreshGenerator refresh_token.Generator

	refreshHasher refresh_token.Hasher

	audit audit.Publisher

	refreshTTL time.Duration
}

func NewService(
	transaction transaction.Manager,
	refreshTokens refresh_token.Repository,
	sessions session.Repository,
	accessTokens token.AccessTokenService,
	refreshGenerator refresh_token.Generator,
	refreshHasher refresh_token.Hasher,
	audit audit.Publisher,
	refreshTTL time.Duration,
) *Service {

	return &Service{
		transaction: transaction,

		refreshTokens: refreshTokens,

		sessions: sessions,

		accessTokens: accessTokens,

		refreshGenerator: refreshGenerator,

		refreshHasher: refreshHasher,

		audit: audit,

		refreshTTL: refreshTTL,
	}
}

func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

	hash :=
		s.refreshHasher.Hash(
			cmd.RefreshToken,
		)

	current, err :=
		s.refreshTokens.FindByHash(
			ctx,
			hash,
		)

	if err != nil {

		_ = s.audit.Publish(
			ctx,
			refreshFailedEvent(
				nil,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return nil,
			errs.ErrInvalidRefreshToken
	}

	sessionData, err :=
		s.sessions.FindByID(
			ctx,
			current.SessionID,
		)

	if err != nil {

		_ = s.audit.Publish(
			ctx,
			refreshFailedEvent(
				&current.SessionID,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return nil,
			errs.ErrInvalidRefreshToken
	}

	if current.ConsumedAt != nil {

		_ =
			s.refreshTokens.RevokeFamily(
				ctx,
				current.FamilyID,
				refresh_token.RevokeReasonReplay,
			)

		_ =
			s.audit.Publish(
				ctx,
				refreshReplayEvent(
					sessionData.UserID,
				),
			)

		return nil,
			errs.ErrRefreshTokenReplay
	}

	if current.RevokedAt != nil ||
		current.ExpiresAt.Before(time.Now()) {

		_ = s.audit.Publish(
			ctx,
			refreshFailedEvent(
				&sessionData.UserID,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return nil,
			errs.ErrInvalidRefreshToken
	}

	if sessionData.RevokedAt != nil ||
		sessionData.ExpiresAt.Before(time.Now()) {

		_ = s.audit.Publish(
			ctx,
			refreshFailedEvent(
				&sessionData.UserID,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return nil,
			errs.ErrInvalidRefreshToken
	}

	rawToken, err :=
		s.refreshGenerator.Generate()

	if err != nil {
		return nil, err
	}

	newRefreshToken :=
		refresh_token.Token{

			ID: uuid.New(),

			SessionID: current.SessionID,

			FamilyID: current.FamilyID,

			ParentTokenID: &current.ID,

			Hash: s.refreshHasher.Hash(
				rawToken,
			),

			ExpiresAt: time.Now().
				Add(
					s.refreshTTL,
				),
		}

	err =
		s.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				refreshRepo :=
					s.refreshTokens.WithTx(tx)

				consumed, err :=
					refreshRepo.Consume(
						ctx,
						current.ID,
					)

				if err != nil {
					return err
				}

				if !consumed {

					return errs.ErrRefreshTokenReplay
				}

				err =
					refreshRepo.Create(
						ctx,
						newRefreshToken,
					)

				if err != nil {
					return err
				}

				sessionRepo :=
					s.sessions.WithTx(tx)

				return sessionRepo.UpdateLastRefreshedAt(
					ctx,
					current.SessionID,
				)
			},
		)

	if err != nil {

		if errors.Is(
			err,
			errs.ErrRefreshTokenReplay,
		) {

			_ =
				s.refreshTokens.RevokeFamily(
					ctx,
					current.FamilyID,
					refresh_token.RevokeReasonReplay,
				)

			_ =
				s.audit.Publish(
					ctx,
					refreshReplayEvent(
						sessionData.UserID,
					),
				)

		}

		return nil, err
	}

	accessToken, err :=
		s.accessTokens.Generate(
			token.Claims{

				UserID: sessionData.UserID,
			},
		)

	if err != nil {
		return nil, err
	}

	_ =
		s.audit.Publish(
			ctx,
			refreshSuccessEvent(
				sessionData.UserID,
			),
		)

	return &Result{

		AccessToken: accessToken.Token,

		RefreshToken: rawToken,

		ExpiresIn: int64(
			time.Until(
				accessToken.ExpiresAt,
			).
				Seconds(),
		),
	}, nil
}
