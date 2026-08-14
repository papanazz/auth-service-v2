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

	IPAddress string

	UserAgent string
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
// logged out) succeed silently. Verified under real concurrency, not
// just sequential calls — see TestService_Handle_ConcurrentLogoutsAllSucceed.
func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) error {

	//
	// 1. Locate the presented token
	//

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
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return errs.ErrInvalidRefreshToken
	}

	//
	// 2. Resolve its owning session
	//
	// Only the session ID is known if this fails — see docs/refresh.txt's
	// CROSS-CUTTING FIXES for why that distinction (never the user ID)
	// matters for the audit trail.
	//

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
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidRefreshToken.Message,
			),
		)

		return errs.ErrInvalidRefreshToken
	}

	//
	// 3. Revoke the session and its whole refresh-token family
	//
	// No expiry/revocation checks on the presented token or session
	// before acting, unlike refresh — logout's job is "make sure this
	// session is dead," which an already-expired, already-consumed, or
	// already-revoked token still correctly identifies. Session.Revoke
	// and RevokeFamily are themselves guarded on revoked_at IS NULL, so
	// a second revoke is a no-op rather than clobbering the original
	// revocation's reason/timestamp — this is what makes step 3 safe to
	// run unconditionally instead of checking state first.
	//

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

	//
	// 4. Publish audit event
	//

	_ =
		s.audit.Publish(
			ctx,
			logoutSuccessEvent(
				sessionData.UserID,
				sessionData.ID,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		)

	return nil
}
