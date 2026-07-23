package password

import "errors"

var (
	ErrInvalidPassword = errors.New(
		"invalid password",
	)

	ErrInvalidHash = errors.New(
		"invalid password hash",
	)

	ErrWeakPassword = errors.New(
		"password does not meet security requirements",
	)
)
