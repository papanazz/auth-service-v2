package register

import (
	"context"
	"errors"
	"strings"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/auth"
	"github.com/papanazz/auth-service-v2/internal/domain/password"
	"github.com/papanazz/auth-service-v2/internal/domain/user"

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
	userRepository user.Repository

	passwordHasher password.Hasher

	passwordPolicy password.Policy

	audit audit.Publisher

	attemptTracker auth.AttemptTracker

	policy SecurityPolicy
}

func NewService(

	userRepository user.Repository,

	passwordHasher password.Hasher,

	passwordPolicy password.Policy,

	audit audit.Publisher,

	attemptTracker auth.AttemptTracker,

	policy SecurityPolicy,

) *RegisterService {

	return &RegisterService{

		userRepository: userRepository,

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
		strings.ToLower(
			strings.TrimSpace(
				cmd.Email,
			),
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
	// 5. Hash the password and persist the account
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
	// behind email verification. That flow doesn't exist yet — there is no
	// verification token, no delivery mechanism, and no endpoint to
	// complete it — so activate the account immediately rather than
	// stranding every new user in a state nothing can ever clear. See
	// docs/register.md.
	account.Status = user.StatusActive

	err =
		s.userRepository.Create(
			ctx,
			account,
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
			registeredEvent(
				account.ID,
				account.Email,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		)

	return &Result{

		ID: account.ID.String(),

		Email: account.Email,
	}, nil

}
