package register

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	domainEmail "github.com/papanazz/auth-service-v2/internal/domain/email"
	"github.com/papanazz/auth-service-v2/internal/domain/password"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"

	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	Email string

	Password string

	IPAddress string

	UserAgent string
}

type Result struct {
	ID string `json:"id"`

	Email string `json:"email"`
}

type RegisterService struct {
	transaction transaction.Manager

	userRepository user.Repository

	verificationTokens verification.Repository

	verificationCache verification.Cache

	verificationGenerator verification.Generator

	verificationHasher verification.Hasher

	emailPublisher domainEmail.Publisher

	passwordHasher password.Hasher

	passwordPolicy password.Policy

	audit audit.Publisher

	attemptTracker auth.AttemptTracker

	policy SecurityPolicy
}

func NewService(

	transaction transaction.Manager,

	userRepository user.Repository,

	verificationTokens verification.Repository,

	verificationCache verification.Cache,

	verificationGenerator verification.Generator,

	verificationHasher verification.Hasher,

	emailPublisher domainEmail.Publisher,

	passwordHasher password.Hasher,

	passwordPolicy password.Policy,

	audit audit.Publisher,

	attemptTracker auth.AttemptTracker,

	policy SecurityPolicy,

) *RegisterService {

	return &RegisterService{

		transaction: transaction,

		userRepository: userRepository,

		verificationTokens: verificationTokens,

		verificationCache: verificationCache,

		verificationGenerator: verificationGenerator,

		verificationHasher: verificationHasher,

		emailPublisher: emailPublisher,

		passwordHasher: passwordHasher,

		passwordPolicy: passwordPolicy,

		audit: audit,

		attemptTracker: attemptTracker,

		policy: policy,
	}

}

func (s *RegisterService) Handle(

	ctx context.Context,

	cmd Command,

) (
	*Result,
	error,
) {

	//
	// 1. Normalize and validate input
	//

	email :=
		user.NormalizeEmail(
			cmd.Email,
		)

	if err := Validate(email); err != nil {

		return nil, err

	}

	//
	// 2. Rate limit check
	//
	// Every attempt counts toward the limit, not just failures — unlike
	// login's credential-based limiter (which only counts wrong-password
	// guesses), the threat register defends against is volume from one
	// source: mass account creation and email-enumeration probing both
	// generate many attempts regardless of whether any individual one
	// succeeds. So the counter is incremented unconditionally below,
	// right after the cheap format checks and before anything that
	// touches the database.
	//

	allowed, err :=
		s.attemptTracker.Check(
			ctx,
			authattempt.RegisterIP(
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

	// RecordFailure is, under the hood, just "increment the sliding window
	// counter" — the name reflects login's only current use (count
	// wrong-password guesses), not a hard requirement that the call
	// represents a failure.
	_ =
		s.attemptTracker.RecordFailure(
			ctx,
			authattempt.RegisterIP(
				cmd.IPAddress,
			),
			s.policy.IP,
		)

	//
	// 3. Enforce password policy
	//

	if err :=
		s.passwordPolicy.Validate(
			cmd.Password,
		); err != nil {

		return nil, err

	}

	//
	// 4. Reject a duplicate account
	//
	// Racy against a concurrent registration for the same email — the
	// database's unique constraint is the real guarantee. This check exists
	// to give the common case a clean ErrUserAlreadyExists instead of a
	// raw constraint-violation error.
	//

	_, err = s.userRepository.FindByEmail(
		ctx,
		email,
	)

	switch {

	case err == nil:

		return nil,
			errs.ErrUserAlreadyExists

	case errors.Is(
		err,
		errs.ErrUserNotFound,
	):

		// continue

	default:

		return nil, err

	}

	//
	// 5. Hash the password
	//

	hash, err :=
		s.passwordHasher.Hash(
			cmd.Password,
		)

	if err != nil {

		return nil, err

	}

	account :=
		user.New(
			email,
			hash,
		)

	// user.New defaults to StatusPending, which is meant to gate login
	// behind email verification. Login/refresh/logout deliberately do not
	// gate on EmailVerifiedAt (see docs/login.md) — verification below is
	// informational, not an access control — so activate the account
	// immediately rather than stranding every new user in a state only
	// verify-email can clear. See docs/register.md.
	account.Status = user.StatusActive

	//
	// 6. Persist the account and its verification token atomically
	//
	// Both or neither: a token that failed to persist would leave a real
	// account with no way to receive one until a resend, which is
	// recoverable, but there is no reason to accept that inconsistency
	// when both writes fit in one transaction.
	//

	rawToken, err :=
		s.verificationGenerator.Generate()

	if err != nil {

		return nil, err
	}

	verificationTokenExpiresAt :=
		time.Now().
			Add(s.policy.EmailVerificationTokenTTL).
			UTC()

	verificationToken :=
		verification.Token{

			ID: uuid.New(),

			UserID: account.ID,

			Hash: s.verificationHasher.Hash(rawToken),

			ExpiresAt: verificationTokenExpiresAt,
		}

	err =
		s.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				if err := s.userRepository.WithTx(tx).Create(
					ctx,
					account,
				); err != nil {

					return err
				}

				return s.verificationTokens.WithTx(tx).Create(
					ctx,
					verificationToken,
				)
			},
		)

	if err != nil {

		return nil, err

	}

	//
	// 7. Publish audit event and the verification email
	//
	// Both best-effort and both after commit: an outage in either must
	// not fail a registration that already succeeded, and neither should
	// run against a transaction that might still roll back.
	//

	_ =
		s.audit.Publish(
			ctx,
			registeredEvent(
				account.ID,
				account.Email,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		)

	_ =
		s.verificationCache.StoreRawToken(
			ctx,
			verificationToken.ID,
			rawToken,
			s.policy.EmailVerificationTokenTTL,
		)

	_ =
		s.emailPublisher.PublishVerificationEmail(
			ctx,
			domainEmail.VerificationEmail{

				To: account.Email,

				Token: rawToken,

				ExpiresAt: verificationTokenExpiresAt,
			},
		)

	return &Result{

		ID: account.ID.String(),

		Email: account.Email,
	}, nil

}
