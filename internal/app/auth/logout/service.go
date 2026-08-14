package logout

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	RefreshToken string
}

type Service struct {
	transaction transaction.Manager

	refreshTokens refresh_token.Repository

	sessions session.Repository

	refreshHasher refresh_token.Hasher

	audit audit.Publisher
}

func NewService(
	transaction transaction.Manager,
	refreshTokens refresh_token.Repository,
	sessions session.Repository,
	refreshHasher refresh_token.Hasher,
	audit audit.Publisher,
) *Service {

	return &Service{
		transaction: transaction,

		refreshTokens: refreshTokens,

		sessions: sessions,

		refreshHasher: refreshHasher,

		audit: audit,
	}
}

// Handle terminates the session tied to the supplied refresh token.
//
// Revocation is idempotent: logging out a session that is already
// terminated is not an error, so repeated or racing logout calls
// (e.g. an app calling logout on teardown after the user already
// logged out) succeed silently.
func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) error {

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
			logoutFailedEvent(
				nil,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return errs.ErrInvalidRefreshToken
	}

	sessionData, err :=
		s.sessions.FindByID(
			ctx,
			current.SessionID,
		)

	if err != nil {
		_ = s.audit.Publish(
			ctx,
			logoutFailedEvent(
				&current.SessionID,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return errs.ErrInvalidRefreshToken
	}

	err =
		s.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				sessionRepo :=
					s.sessions.WithTx(tx)

				err :=
					sessionRepo.Revoke(
						ctx,
						current.SessionID,
						session.RevokeUserLogout,
					)

				if err != nil {
					return err
				}

				refreshRepo :=
					s.refreshTokens.WithTx(tx)

				return refreshRepo.RevokeFamily(
					ctx,
					current.FamilyID,
					refresh_token.RevokeReasonLogout,
				)
			},
		)

	if err != nil {
		return err
	}

	_ =
		s.audit.Publish(
			ctx,
			logoutSuccessEvent(
				sessionData.UserID,
				sessionData.ID,
			),
		)

	return nil
}
