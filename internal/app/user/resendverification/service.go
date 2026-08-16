package resendverification

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	domainEmail "github.com/papanazz/auth-service-v2/internal/domain/email"
	"github.com/papanazz/auth-service-v2/internal/domain/logging"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"

	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	Email string

	IPAddress string

	UserAgent string
}

type Service struct {
	users user.Repository

	tokens verification.Repository

	cache verification.Cache

	generator verification.Generator

	hasher verification.Hasher

	emailPublisher domainEmail.Publisher

	audit audit.Publisher

	attemptTracker auth.AttemptTracker

	logger logging.Logger

	policy SecurityPolicy
}

func NewService(
	users user.Repository,
	tokens verification.Repository,
	cache verification.Cache,
	generator verification.Generator,
	hasher verification.Hasher,
	emailPublisher domainEmail.Publisher,
	audit audit.Publisher,
	attemptTracker auth.AttemptTracker,
	logger logging.Logger,
	policy SecurityPolicy,
) *Service {

	return &Service{
		users: users,

		tokens: tokens,

		cache: cache,

		generator: generator,

		hasher: hasher,

		emailPublisher: emailPublisher,

		audit: audit,

		attemptTracker: attemptTracker,

		logger: logger,

		policy: policy,
	}
}

// Handle always succeeds from the caller's point of view — whether the
// email is unregistered, already verified, or genuinely needs a new
// token, the response is identical. See docs/email-verification.md
// Decisions: distinguishing these cases in the response would let this
// endpoint be used to enumerate registered (or verified) accounts by
// email, the same class of leak login's dummy-hash verification exists
// to close for passwords.
func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) error {

	email := user.NormalizeEmail(cmd.Email)

	//
	// 1. Rate limit check
	//
	// Every attempt counts, not just ones that actually send an email —
	// same reasoning as register's limiter: the cases this endpoint must
	// not leak (unknown email, already verified) are exactly the ones an
	// enumeration attempt generates in bulk.
	//

	allowed, err :=
		s.attemptTracker.Check(
			ctx,
			authattempt.ResendVerificationIP(cmd.IPAddress),
			s.policy.IP,
		)

	if err != nil {
		return err
	}

	if !allowed {
		return errs.ErrTooManyRequests
	}

	if err :=
		s.attemptTracker.RecordFailure(
			ctx,
			authattempt.ResendVerificationIP(cmd.IPAddress),
			s.policy.IP,
		); err != nil {

		s.logger.Error(ctx, "[ResendVerification] rate limit counter increment failed", err, nil)
	}

	//
	// 2. Resolve the account
	//
	// Unknown email or already verified: no-op, same response as a real
	// send.
	//

	account, err := s.users.FindByEmail(ctx, email)

	if err != nil {

		if errors.Is(err, errs.ErrUserNotFound) {
			return nil
		}

		return err
	}

	if account.EmailVerifiedAt != nil {
		return nil
	}

	//
	// 3. Reuse the active token if one exists and its raw value is
	// still cached; otherwise mint a fresh one
	//

	rawToken, expiresAt, err := s.reuseOrMint(ctx, account.ID)

	if err != nil {
		return err
	}

	//
	// 4. Publish the email and audit the send
	//

	if err :=
		s.emailPublisher.PublishVerificationEmail(
			ctx,
			domainEmail.VerificationEmail{

				To: account.Email,

				Token: rawToken,

				ExpiresAt: expiresAt,
			},
		); err != nil {

		s.logger.Error(ctx, "[ResendVerification] verification email publish failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	if err :=
		s.audit.Publish(
			ctx,
			verificationEmailSentEvent(
				account.ID,
				account.Email,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[ResendVerification] audit publish failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	return nil
}

// reuseOrMint returns the raw token and expiry to publish: the existing
// active token's raw value if one is cached, or a freshly minted one.
func (s *Service) reuseOrMint(
	ctx context.Context,
	userID uuid.UUID,
) (
	string,
	time.Time,
	error,
) {

	existing, err := s.tokens.FindActiveByUserID(ctx, userID)

	if err != nil && !errors.Is(err, errs.ErrVerificationTokenNotFound) {

		return "", time.Time{}, err
	}

	if existing != nil {

		raw, found, err := s.cache.GetRawToken(ctx, existing.ID)

		if err != nil {
			return "", time.Time{}, err
		}

		if found {
			return raw, existing.ExpiresAt, nil
		}

		// The DB record is still valid but its raw value is gone from
		// the cache (evicted, Redis restarted, ...). The old token
		// stays valid until it expires on its own — harmless, since
		// multiple concurrently-valid tokens for one user are fine —
		// mint a new one instead of leaving the caller with nothing to
		// send.
	}

	raw, err := s.generator.Generate()

	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt := time.Now().Add(s.policy.TokenTTL).UTC()

	token :=
		verification.Token{

			ID: uuid.New(),

			UserID: userID,

			Hash: s.hasher.Hash(raw),

			ExpiresAt: expiresAt,
		}

	if err := s.tokens.Create(ctx, token); err != nil {
		return "", time.Time{}, err
	}

	// Best-effort: a cache-store failure only costs a future resend the
	// ability to reuse this exact token — it can still mint a new one.
	if err := s.cache.StoreRawToken(ctx, token.ID, raw, s.policy.TokenTTL); err != nil {

		s.logger.Error(ctx, "[ResendVerification] verification token cache store failed", err, map[string]any{
			"user_id": userID,
		})
	}

	return raw, expiresAt, nil
}
