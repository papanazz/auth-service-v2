package register

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/password"

	"github.com/papanazz/auth-service-v2/internal/domain/user"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	Email string

	Password string
}

type Result struct {
	ID string `json:"id"`

	Email string `json:"email"`
}

type RegisterService struct {
	userRepository user.Repository

	passwordHasher password.Hasher

	passwordPolicy password.Policy
}

func NewService(

	userRepository user.Repository,

	passwordHasher password.Hasher,

	passwordPolicy password.Policy,

) *RegisterService {

	return &RegisterService{

		userRepository: userRepository,

		passwordHasher: passwordHasher,

		passwordPolicy: passwordPolicy,
	}

}

func (s *RegisterService) Handle(

	ctx context.Context,

	cmd Command,

) (
	*Result,
	error,
) {

	email :=
		strings.ToLower(
			strings.TrimSpace(
				cmd.Email,
			),
		)

	if err := Validate(email); err != nil {

		return nil, err

	}

	if err :=
		s.passwordPolicy.Validate(
			cmd.Password,
		); err != nil {

		return nil, err

	}

	_, err :=
		s.userRepository.FindByEmail(
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

	hash, err :=
		s.passwordHasher.Hash(
			cmd.Password,
		)

	if err != nil {

		return nil, err

	}

	account :=
		user.User{

			ID: uuid.New(),

			Email: email,

			PasswordHash: hash,

			Status: user.StatusActive,

			EmailVerifiedAt: nil,
		}

	err =
		s.userRepository.Create(
			ctx,
			account,
		)

	if err != nil {

		return nil, err

	}

	return &Result{

		ID: account.ID.String(),

		Email: account.Email,
	}, nil

}
