package audit

import (
	"time"

	"github.com/google/uuid"
)

type EventType string

const (
	EventUserRegistered EventType = "USER_REGISTERED"

	EventLoginSuccess EventType = "LOGIN_SUCCESS"

	EventLoginFailed EventType = "LOGIN_FAILED"

	EventLogout EventType = "LOGOUT"

	EventLogoutAll EventType = "LOGOUT_ALL"

	EventTokenRefresh EventType = "TOKEN_REFRESH"

	EventTokenRefreshFailed EventType = "TOKEN_REFRESH_FAILED"

	EventTokenReuseDetected EventType = "TOKEN_REUSE_DETECTED"

	EventPasswordChanged EventType = "PASSWORD_CHANGED"

	EventAccountLocked EventType = "ACCOUNT_LOCKED"

	EventEmailVerified EventType = "EMAIL_VERIFIED"

	EventVerificationEmailSent EventType = "VERIFICATION_EMAIL_SENT"

	// EventOAuthAccountLinked fires only when an existing account gains
	// a new linked identity (docs/adr/0001-oauth-client-and-account-linking.md
	// case 3, the auto-link branch) — a genuinely new fact about the
	// account that no other event type captures. A returning user
	// signing in via an already-linked identity, or a brand-new account
	// created via OAuth, are both ordinary EventLoginSuccess /
	// EventUserRegistered — OAuth isn't a different kind of login or
	// registration, so it doesn't get its own event type for those.
	EventOAuthAccountLinked EventType = "OAUTH_ACCOUNT_LINKED"
)

type Event struct {
	ID uuid.UUID

	Type EventType

	UserID *uuid.UUID

	// Useful when authentication fails
	// before identifying a user.
	Email string

	SessionID *uuid.UUID

	IPAddress string

	UserAgent string

	Success bool

	Reason *string

	Metadata map[string]any

	CreatedAt time.Time
}

func New(
	eventType EventType,
) Event {

	return Event{

		ID: uuid.New(),

		Type: eventType,

		Metadata: make(
			map[string]any,
		),

		CreatedAt: time.Now().UTC(),
	}
}
