package errs

import "errors"

// ErrOAuthIdentityNotFound is a raw sentinel, not an *Error — it never
// reaches a client directly. oauthcallback uses it to distinguish "no
// row for this provider identity" (continue resolving whether this is a
// new account or a collision) from a genuine repository failure, which
// must propagate unmasked instead of being treated as "unlinked."
// Mirrors ErrRefreshTokenNotFound, ErrSessionNotFound,
// ErrVerificationTokenNotFound.
var ErrOAuthIdentityNotFound = errors.New(
	"oauth identity not found",
)
