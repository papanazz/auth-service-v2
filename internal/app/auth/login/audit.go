package login

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

func loginSuccessEvent(
	userID uuid.UUID,
	ip string,
	userAgent string,
) audit.Event {

	return audit.Event{

		ID: uuid.New(),

		Type: "LOGIN_SUCCESS",

		UserID: userID,

		IpAddress: ip,

		UserAgent: userAgent,

		Success: true,
	}

}

func loginFailedEvent(
	userID *uuid.UUID,
	email string,
	ip string,
	userAgent string,
	reason string,
) audit.Event {

	events := audit.Event{

		ID: uuid.New(),

		Type: "LOGIN_FAILED",

		Email: email,

		IpAddress: ip,

		UserAgent: userAgent,

		Success: false,

		Reason: reason,
	}

	if userID != nil {
		events.UserID = *userID
	}

	return events
}
