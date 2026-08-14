package logout

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

func logoutSuccessEvent(
	userID uuid.UUID,
	sessionID uuid.UUID,
	ip string,
	userAgent string,
) audit.Event {

	event :=
		audit.New(
			audit.EventLogout,
		)

	event.UserID = &userID

	event.SessionID = &sessionID

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = true

	return event
}

func logoutFailedEvent(
	sessionID *uuid.UUID,
	ip string,
	userAgent string,
	reason string,
) audit.Event {

	event :=
		audit.New(
			audit.EventLogout,
		)

	event.SessionID = sessionID

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = false

	event.Reason = &reason

	return event
}
