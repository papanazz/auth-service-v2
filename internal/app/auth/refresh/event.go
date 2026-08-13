package refresh

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

func refreshSuccessEvent(
	userID uuid.UUID,
) audit.Event {

	return audit.Event{

		ID: uuid.New(),

		Type: audit.EventTokenRefresh,

		UserID: &userID,

		Success: true,
	}
}

func refreshFailedEvent(
	userID *uuid.UUID,
	reason string,
) audit.Event {

	event :=
		audit.Event{

			ID: uuid.New(),

			Type: audit.EventTokenRefreshFailed,

			Success: false,

			Reason: &reason,
		}

	if userID != nil {
		event.UserID = userID
	}

	return event
}

func refreshReplayEvent(
	userID uuid.UUID,
) audit.Event {

	message := "refresh token replay detected"

	return audit.Event{

		ID: uuid.New(),

		Type: audit.EventTokenReuseDetected,

		UserID: &userID,

		Success: false,

		Reason: &message,
	}
}
