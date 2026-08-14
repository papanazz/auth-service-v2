package errs

import "errors"

var (
	ErrVerificationTokenNotFound = errors.New(
		"verification token not found",
	)
)
