package errs

var (
	ErrInvalidRequest = New(
		CodeInvalidRequest,
		"invalid request",
	)

	ErrInvalidEmail = New(
		CodeInvalidEmail,
		"invalid email",
	)

	ErrWeakPassword = New(
		CodeWeakPassword,
		"password does not meet security requirements",
	)

	ErrUserAlreadyExists = New(
		CodeUserAlreadyExists,
		"user already exists",
	)

	ErrUserNotFound = New(
		CodeUserNotFound,
		"user not found",
	)

	ErrInvalidCredentials = New(
		CodeInvalidCredentials,
		"invalid credentials",
	)

	ErrEmailNotVerified = New(
		CodeEmailNotVerified,
		"email has not been verified",
	)

	ErrAccountLocked = New(
		CodeAccountLocked,
		"account is locked",
	)

	ErrTooManyRequests = New(
		CodeTooManyRequest,
		"too many requests",
	)

	ErrDeviceSessionActive = New(
		CodeDeviceSessionActive,
		"an active session already exists for this device",
	)
)
