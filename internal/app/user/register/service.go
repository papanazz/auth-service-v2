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
	Email    string
	Password string
}

type Result struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type RegisterService struct {
	userRepository     user.Repository
	passwordRepository password.Repository
}

func NewService(userRepository user.Repository, passwordRepository password.Repository) *RegisterService {
	return &RegisterService{
		userRepository:     userRepository,
		passwordRepository: passwordRepository,
	}
}

func (h *RegisterService) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

	email := strings.ToLower(strings.TrimSpace(cmd.Email))

	if err := Validate(email, cmd.Password); err != nil {
		return nil, err
	}

	_, err := h.userRepository.FindByEmail(ctx, email)

	switch {

	case err == nil:
		return nil, errs.ErrUserAlreadyExists

	case errors.Is(err, errs.ErrUserNotFound):
		break

	default:
		return nil, err
	}

	hash, err := h.passwordRepository.Hash(cmd.Password)
	if err != nil {
		return nil, err
	}

	u := user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: hash,
		Status:       user.StatusActive,
	}

	if err := h.userRepository.Create(ctx, u); err != nil {
		return nil, err
	}

	return &Result{
		ID:    u.ID.String(),
		Email: u.Email,
	}, nil
}
