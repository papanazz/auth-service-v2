package errs

import "errors"

var (
	ErrSessionNotFound = errors.New(
		"session not found",
	)
)
