package errs

import "errors"

// ErrRefreshTokenNotFound is a raw sentinel, not an *Error — it never
// reaches a client directly. The service layer translates it into
// ErrInvalidRefreshToken (unknown token and expired-but-never-consumed
// token deliberately look identical to a caller), and distinguishes it
// from a genuine repository failure, which must propagate as-is instead
// of being masked as "invalid token." Mirrors ErrSessionNotFound and
// ErrVerificationTokenNotFound.
var ErrRefreshTokenNotFound = errors.New(
	"refresh token not found",
)

var (
	ErrInvalidRefreshToken = New(
		CodeInvalidRefreshToken,
		"invalid refresh token",
	)

	ErrRefreshTokenReplay = New(
		CodeRefreshTokenReplay,
		"refresh token replay detected",
	)
)
