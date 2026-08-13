package errs

type Code string

const (
	CodeInternal Code = "INTERNAL_ERROR"

	CodeInvalidRequest Code = "INVALID_REQUEST"

	CodeInvalidEmail Code = "INVALID_EMAIL"

	CodeWeakPassword Code = "WEAK_PASSWORD"

	CodeUserAlreadyExists Code = "USER_ALREADY_EXISTS"

	CodeUserNotFound Code = "USER_NOT_FOUND"

	CodeInvalidCredentials Code = "INVALID_CREDENTIALS"

	CodeEmailNotVerified Code = "EMAIL_NOT_VERIFIED"

	CodeAccountLocked Code = "ACCOUNT_LOCKED"

	CodeTooManyRequest Code = "TOO_MANY_REQUEST"

	CodeInvalidRefreshToken Code = "AUTH_INVALID_REFRESH_TOKEN"

	CodeRefreshTokenReplay Code = "AUTH_REFRESH_TOKEN_REPLAY"
)
