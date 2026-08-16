package sessionissuer

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

// Policy holds the TTLs and grace period IssueForDevice needs — split
// out of login.SecurityPolicy when this package was extracted from
// login.Service, so both login and oauthcallback configure the same
// values once instead of each carrying its own copy.
type Policy struct {
	RefreshTokenTTL time.Duration

	// SessionTTL must be >= RefreshTokenTTL. A refresh token is only
	// accepted while its session is still active, so a shorter session
	// TTL would reject tokens that have not expired yet.
	SessionTTL time.Duration

	// DeviceGracePeriod bounds how a new session request is treated
	// when the same device already holds an active session: within
	// this window of that session's creation, the new one supersedes
	// it; past it, the request is rejected. See docs/login.md for the
	// full rationale.
	DeviceGracePeriod time.Duration
}

type Result struct {
	AccessToken string

	RefreshToken string

	ExpiresIn int64

	SessionID uuid.UUID
}

// Issuer mints a session, a refresh token, and an access token for one
// account on one device — the transactional core that used to live
// inline in login.Service (flow steps 6-7) before OAuth login needed
// the identical logic. Both login and oauthcallback depend on this same
// instance rather than each having their own copy, so the two ways to
// authenticate can't drift apart in session-issuance behavior. See
// docs/oauth.md and docs/adr/0001-oauth-client-and-account-linking.md.
type Issuer struct {
	transaction transaction.Manager

	sessions session.Repository

	refreshTokens refresh_token.Repository

	accessTokens token.AccessTokenService

	refreshGenerator refresh_token.Generator

	refreshHasher refresh_token.Hasher

	policy Policy
}

func NewIssuer(
	transaction transaction.Manager,
	sessions session.Repository,
	refreshTokens refresh_token.Repository,
	accessTokens token.AccessTokenService,
	refreshGenerator refresh_token.Generator,
	refreshHasher refresh_token.Hasher,
	policy Policy,
) *Issuer {

	return &Issuer{

		transaction: transaction,

		sessions: sessions,

		refreshTokens: refreshTokens,

		accessTokens: accessTokens,

		refreshGenerator: refreshGenerator,

		refreshHasher: refreshHasher,

		policy: policy,
	}
}

// IssueForDevice creates a new session bound to (accountID, deviceID)
// and its family-root refresh token, atomically. A device may hold at
// most one active session (uq_sessions_active_device); within
// Policy.DeviceGracePeriod of that session's creation the new request
// supersedes it, past it errs.ErrDeviceSessionActive is returned
// unwrapped — callers that want to audit that case specifically should
// check errors.Is against it.
func (i *Issuer) IssueForDevice(
	ctx context.Context,
	accountID uuid.UUID,
	deviceID string,
	deviceName string,
	deviceType session.DeviceType,
	ipAddress string,
	userAgent string,
) (*Result, error) {

	sessionID := uuid.New()

	familyID := uuid.New()

	rawRefreshToken, err := i.refreshGenerator.Generate()

	if err != nil {
		return nil, err
	}

	// No database dependency.
	accessToken, err :=
		i.accessTokens.Generate(
			token.Claims{

				UserID: accountID,

				SessionID: sessionID,
			},
		)

	if err != nil {
		return nil, err
	}

	err =
		i.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				now := time.Now().UTC()

				txSessionRepo := i.sessions.WithTx(tx)

				// A device may hold at most one active session
				// (uq_sessions_active_device). The lock below serializes
				// concurrent requests for this device so the read that
				// follows cannot go stale before this transaction acts
				// on it — without it, two concurrent retries could both
				// see the same existing session as supersede-able and
				// race each other into the unique constraint.
				if err :=
					txSessionRepo.LockDeviceSlot(
						ctx,
						accountID,
						deviceID,
					); err != nil {

					return err
				}

				existingSession, err :=
					txSessionRepo.FindActiveByUserAndDevice(
						ctx,
						accountID,
						deviceID,
					)

				if err != nil && !errors.Is(err, errs.ErrSessionNotFound) {

					return err
				}

				if existingSession != nil {

					if time.Since(existingSession.CreatedAt) > i.policy.DeviceGracePeriod {

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

							UserID: accountID,

							DeviceID: deviceID,

							DeviceName: deviceName,

							DeviceType: deviceType,

							IPAddress: ipAddress,

							UserAgent: userAgent,

							LastUsedAt: &now,

							ExpiresAt: now.
								Add(
									i.policy.SessionTTL,
								).
								UTC(),

							CreatedAt: now.UTC(),
						},
					)

				if err != nil {
					return err
				}

				txRefreshRepo := i.refreshTokens.WithTx(tx)

				return txRefreshRepo.Create(
					ctx,
					refresh_token.Token{

						ID: uuid.New(),

						SessionID: sessionID,

						FamilyID: familyID,

						ParentTokenID: nil,

						Hash: i.refreshHasher.Hash(
							rawRefreshToken,
						),

						ExpiresAt: time.Now().
							Add(
								i.policy.RefreshTokenTTL,
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

	return &Result{

		AccessToken: accessToken.Token,

		RefreshToken: rawRefreshToken,

		ExpiresIn: int64(
			time.Until(
				accessToken.ExpiresAt,
			).Seconds(),
		),

		SessionID: sessionID,
	}, nil
}
