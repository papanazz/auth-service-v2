package errs

var (
	ErrInvalidRefreshToken = New(
		"AUTH_INVALID_REFRESH_TOKEN",
		"invalid refresh token",
	)

	ErrRefreshTokenReplay = New(
		"AUTH_REFRESH_TOKEN_REPLAY",
		"refresh token replay detected",
	)
)
