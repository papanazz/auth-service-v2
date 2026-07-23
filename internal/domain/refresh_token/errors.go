package refresh_token

import "errors"

var (
	ErrAlreadyConsumed = errors.New(
		"refresh token already consumed",
	)

	ErrInvalidToken = errors.New(
		"invalid refresh token",
	)

	ErrExpired = errors.New(
		"refresh token expired",
	)

	ErrConsumed = errors.New(
		"refresh token already consumed",
	)

	ErrRevoked = errors.New(
		"refresh token revoked",
	)
)
