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
