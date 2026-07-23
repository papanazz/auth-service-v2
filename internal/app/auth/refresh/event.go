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

		Type: "REFRESH_SUCCESS",

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

			Type: "REFRESH_FAILED",

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

		Type: "REFRESH_TOKEN_REPLAY",

		UserID: &userID,

		Success: false,

		Reason: &message,
	}
}
