package password

import "errors"

var (
	ErrInvalidPassword = errors.New("invalid password")

	ErrInvalidHash = errors.New("invalid password hash")
)
