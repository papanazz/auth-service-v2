package resendverification

import (
	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
)

func verificationEmailSentEvent(
	userID uuid.UUID,
	email string,
	ip string,
	userAgent string,
) audit.Event {

	event :=
		audit.New(
			audit.EventVerificationEmailSent,
		)

	event.UserID = &userID

	event.Email = email

	event.IPAddress = ip

	event.UserAgent = userAgent

	event.Success = true

	return event
}
