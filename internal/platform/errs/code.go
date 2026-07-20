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
)
