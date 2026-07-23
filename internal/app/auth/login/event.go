package login

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

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
