package oauthcallback

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

// loginSuccessEvent/loginFailedEvent deliberately mirror
// login/event.go's — see docs/oauth.md: OAuth login is audited exactly
// like password login, not as a different kind of event, since from the
// audit trail's point of view it is the same thing happening a
// different way.

func loginSuccessEvent(
	userID uuid.UUID,
	sessionID uuid.UUID,
	ip string,
	userAgent string,
) audit.Event {

	event :=
		audit.New(
			audit.EventLoginSuccess,
		)

	event.UserID = &userID

	event.SessionID = &sessionID

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = true

	return event
}

func loginFailedEvent(
	userID *uuid.UUID,
	email string,
	ip string,
	userAgent string,
	reason string,
) audit.Event {

	event :=
		audit.New(
			audit.EventLoginFailed,
		)

	event.UserID = userID

	event.Email = email

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = false

	event.Reason = &reason

	return event
}

// registeredEvent mirrors register/event.go's — a brand-new account
// created via OAuth (no email collision) is an ordinary
// USER_REGISTERED, not a different event type.
func registeredEvent(
	userID uuid.UUID,
	email string,
	ip string,
	userAgent string,
) audit.Event {

	event :=
		audit.New(
			audit.EventUserRegistered,
		)

	event.UserID = &userID

	event.Email = email

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = true

	return event
}

// oauthAccountLinkedEvent is the one genuinely new event type this
// feature introduces — see audit.EventOAuthAccountLinked's own doc
// comment for why the auto-link case doesn't fit any existing type.
func oauthAccountLinkedEvent(
	userID uuid.UUID,
	email string,
	ip string,
	userAgent string,
) audit.Event {

	event :=
		audit.New(
			audit.EventOAuthAccountLinked,
		)

	event.UserID = &userID

	event.Email = email

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = true

	return event
}
