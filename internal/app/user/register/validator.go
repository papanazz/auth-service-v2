package register

import (
	"net/mail"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func Validate(
	email string,
) error {

	if _, err :=
		mail.ParseAddress(
			email,
		); err != nil {

		return errs.ErrInvalidEmail
	}

	return nil

}
