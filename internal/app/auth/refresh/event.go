package refresh

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

func refreshSuccessEvent(
	userID uuid.UUID,
	sessionID uuid.UUID,
	ip string,
	userAgent string,
) audit.Event {

	event :=
		audit.New(
			audit.EventTokenRefresh,
		)

	event.UserID = &userID

	event.SessionID = &sessionID

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = true

	return event
}

// refreshFailedEvent takes userID and sessionID as separate optional
// pointers because they resolve independently and can fail independently:
// an unknown token hash yields neither, while a token whose owning session
// has vanished yields the session ID but never the user ID — the lookup
// that would have supplied it is exactly what failed.
func refreshFailedEvent(
	userID *uuid.UUID,
	sessionID *uuid.UUID,
	ip string,
	userAgent string,
	reason string,
) audit.Event {

	event :=
		audit.New(
			audit.EventTokenRefreshFailed,
		)

	event.UserID = userID

	event.SessionID = sessionID

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = false

	event.Reason = &reason

	return event
}

func refreshReplayEvent(
	userID uuid.UUID,
	sessionID uuid.UUID,
	ip string,
	userAgent string,
) audit.Event {

	message := "refresh token replay detected"

	event :=
		audit.New(
			audit.EventTokenReuseDetected,
		)

	event.UserID = &userID

	event.SessionID = &sessionID

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = false

	event.Reason = &message

	return event
}
