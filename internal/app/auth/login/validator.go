package login

import (
	"net/mail"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func Validate(
	email string,
	password string,
) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errs.ErrInvalidEmail
	}

	if password == "" {
		return errs.ErrInvalidRequest
	}

	return nil
}
