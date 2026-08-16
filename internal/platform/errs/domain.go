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

	ErrIdempotencyKeyInProgress = New(
		CodeIdempotencyKeyInProgress,
		"a request with this idempotency key is still being processed",
	)

	ErrIdempotencyKeyConflict = New(
		CodeIdempotencyKeyConflict,
		"this idempotency key was already used with a different request body",
	)

	ErrIdempotencyKeyRequired = New(
		CodeIdempotencyKeyRequired,
		"the Idempotency-Key header is required",
	)

	// ErrInvalidVerificationToken deliberately covers unknown, expired,
	// and already-consumed tokens alike — a client cannot distinguish
	// these from each other, mirroring ErrInvalidRefreshToken's stance
	// on refresh tokens.
	ErrInvalidVerificationToken = New(
		CodeInvalidVerificationToken,
		"invalid or expired verification token",
	)

	// ErrInvalidOAuthState covers an unknown, expired, and
	// already-consumed state alike, the same stance as
	// ErrInvalidVerificationToken above — a client cannot and must not
	// be able to distinguish "this was a replay" from "this just timed
	// out."
	ErrInvalidOAuthState = New(
		CodeInvalidOAuthState,
		"invalid or expired oauth state",
	)

	ErrOAuthProviderUnsupported = New(
		CodeOAuthProviderUnsupported,
		"unsupported oauth provider",
	)
)
