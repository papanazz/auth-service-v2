package logout

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

func logoutSuccessEvent(
	userID uuid.UUID,
	sessionID uuid.UUID,
) audit.Event {

	return audit.Event{

		ID: uuid.New(),

		Type: audit.EventLogout,

		UserID: &userID,

		SessionID: &sessionID,

		Success: true,
	}
}

func logoutFailedEvent(
	sessionID *uuid.UUID,
	reason string,
) audit.Event {

	return audit.Event{

		ID: uuid.New(),

		Type: audit.EventLogout,

		SessionID: sessionID,

		Success: false,

		Reason: &reason,
	}
}
