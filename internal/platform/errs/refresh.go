package errs

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
