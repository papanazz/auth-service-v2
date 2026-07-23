package session

import "errors"

var (
	ErrSessionExpired = errors.New("session expired")

	ErrSessionRevoked = errors.New("session revoked")
)
