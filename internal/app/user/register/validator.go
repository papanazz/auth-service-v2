package register

import (
	"net/mail"
	"unicode"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func Validate(
	email string,
	password string,
) error {

	if _, err := mail.ParseAddress(email); err != nil {
		return errs.ErrInvalidEmail
	}

	if len(password) < 8 {
		return errs.ErrWeakPassword
	}

	var (
		hasUpper bool
		hasLower bool
		hasDigit bool
	)

	for _, r := range password {

		switch {

		case unicode.IsUpper(r):
			hasUpper = true

		case unicode.IsLower(r):
			hasLower = true

		case unicode.IsDigit(r):
			hasDigit = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit {
		return errs.ErrWeakPassword
	}

	return nil
}
