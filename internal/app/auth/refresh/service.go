package refresh

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/logging"
	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	RefreshToken string

	IPAddress string

	UserAgent string
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

	logger logging.Logger

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
	logger logging.Logger,
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

		logger: logger,

		refreshTTL: refreshTTL,
	}
}

func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

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

		// A genuine repository failure is not "unknown token" — see
		// login's identical fix (docs/logging.md) for why conflating
		// the two silently turns an infra outage into a routine-looking
		// 401 instead of the 500 it should be.
		if !errors.Is(err, errs.ErrRefreshTokenNotFound) {
			return nil, err
		}

		if auditErr := s.audit.Publish(
			ctx,
			refreshFailedEvent(
				nil,
				nil,
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidRefreshToken.Message,
			),
		); auditErr != nil {

			s.logger.Error(ctx, "[Refresh] audit publish failed", auditErr, nil)
		}

		return nil,
			errs.ErrInvalidRefreshToken
	}

	//
	// 2. Resolve its owning session
	//
	// A token can outlive the session lookup finding nothing (the FK is
	// ON DELETE CASCADE, but nothing currently deletes sessions outright —
	// this guards the theoretical case, and a corrupted/foreign token
	// hash collision). Only the session ID is known at this point, never
	// the user ID: that is exactly what this lookup failing means we
	// don't have.
	//

	sessionData, err :=
		s.sessions.FindByID(
			ctx,
			current.SessionID,
		)

	if err != nil {

		if !errors.Is(err, errs.ErrSessionNotFound) {
			return nil, err
		}

		if auditErr := s.audit.Publish(
			ctx,
			refreshFailedEvent(
				nil,
				&current.SessionID,
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidRefreshToken.Message,
			),
		); auditErr != nil {

			s.logger.Error(ctx, "[Refresh] audit publish failed", auditErr, map[string]any{
				"session_id": current.SessionID,
			})
		}

		return nil,
			errs.ErrInvalidRefreshToken
	}

	//
	// 3. Detect replay
	//
	// A consumed token presented again is the signature of a stolen token
	// being replayed — rotation means each token is single-use, so a
	// second use can only mean two parties hold the same one. The whole
	// family is revoked, not just this token, since every descendant of a
	// compromised token is equally suspect.
	//

	if current.ConsumedAt != nil {

		if err :=
			s.refreshTokens.RevokeFamily(
				ctx,
				current.FamilyID,
				refresh_token.RevokeReasonReplay,
			); err != nil {

			// Not best-effort in the usual sense — this IS the security
			// response to a detected theft, so a failure here means a
			// still-live sibling token in a compromised family. Worth
			// its own distinct message, not folded into the generic
			// audit-publish-failed line below.
			s.logger.Error(ctx, "[Refresh] revoke family failed after replay detected", err, map[string]any{
				"session_id": current.SessionID,

				"family_id": current.FamilyID,
			})
		}

		if err :=
			s.audit.Publish(
				ctx,
				refreshReplayEvent(
					sessionData.UserID,
					current.SessionID,
					cmd.IPAddress,
					cmd.UserAgent,
				),
			); err != nil {

			s.logger.Error(ctx, "[Refresh] audit publish failed", err, map[string]any{
				"session_id": current.SessionID,
			})
		}

		return nil,
			errs.ErrRefreshTokenReplay
	}

	//
	// 4. Reject a revoked or expired token or session
	//

	if current.RevokedAt != nil ||
		current.ExpiresAt.Before(time.Now()) {

		if err := s.audit.Publish(
			ctx,
			refreshFailedEvent(
				&sessionData.UserID,
				&current.SessionID,
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidRefreshToken.Message,
			),
		); err != nil {

			s.logger.Error(ctx, "[Refresh] audit publish failed", err, map[string]any{
				"user_id": sessionData.UserID,

				"session_id": current.SessionID,
			})
		}

		return nil,
			errs.ErrInvalidRefreshToken
	}

	if sessionData.RevokedAt != nil ||
		sessionData.ExpiresAt.Before(time.Now()) {

		if err := s.audit.Publish(
			ctx,
			refreshFailedEvent(
				&sessionData.UserID,
				&current.SessionID,
				cmd.IPAddress,
				cmd.UserAgent,
				errs.ErrInvalidRefreshToken.Message,
			),
		); err != nil {

			s.logger.Error(ctx, "[Refresh] audit publish failed", err, map[string]any{
				"user_id": sessionData.UserID,

				"session_id": current.SessionID,
			})
		}

		return nil,
			errs.ErrInvalidRefreshToken
	}

	//
	// 5. Mint the replacement token
	//

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

	//
	// 6. Persist the rotation atomically
	//
	// Consume is a conditional UPDATE (consumed_at IS NULL), so exactly one
	// concurrent caller wins it; every loser is treated as a replay below.
	// This is the real concurrency guard — the ConsumedAt check in step 3
	// is only a fast path for a token that is obviously already spent.
	//

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

			if revokeErr :=
				s.refreshTokens.RevokeFamily(
					ctx,
					current.FamilyID,
					refresh_token.RevokeReasonReplay,
				); revokeErr != nil {

				s.logger.Error(ctx, "[Refresh] revoke family failed after replay detected", revokeErr, map[string]any{
					"session_id": current.SessionID,

					"family_id": current.FamilyID,
				})
			}

			if auditErr :=
				s.audit.Publish(
					ctx,
					refreshReplayEvent(
						sessionData.UserID,
						current.SessionID,
						cmd.IPAddress,
						cmd.UserAgent,
					),
				); auditErr != nil {

				s.logger.Error(ctx, "[Refresh] audit publish failed", auditErr, map[string]any{
					"session_id": current.SessionID,
				})
			}

		}

		return nil, err
	}

	//
	// 7. Mint the new access token
	//

	accessToken, err :=
		s.accessTokens.Generate(
			token.Claims{

				UserID: sessionData.UserID,

				SessionID: sessionData.ID,
			},
		)

	if err != nil {
		return nil, err
	}

	//
	// 8. Publish audit event
	//

	if err :=
		s.audit.Publish(
			ctx,
			refreshSuccessEvent(
				sessionData.UserID,
				sessionData.ID,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[Refresh] audit publish failed", err, map[string]any{
			"user_id": sessionData.UserID,

			"session_id": sessionData.ID,
		})
	}

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
