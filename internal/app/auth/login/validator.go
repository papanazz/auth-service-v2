package login

import (
	"net/mail"
	"strings"

	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func Validate(
	email string,
	password string,
	deviceID string,
	deviceType session.DeviceType,
) error {

	if strings.TrimSpace(email) == "" {

		return errs.ErrInvalidEmail
	}

	if _, err := mail.ParseAddress(email); err != nil {

		return errs.ErrInvalidEmail
	}

	if password == "" {

		return errs.ErrInvalidRequest
	}

	// device_id anchors uq_sessions_active_device (one active session per
	// user+device). An empty value is syntactically legal — NOT NULL
	// allows "" — but every client that omitted it would collide into the
	// same device slot, tripping the supersede/reject logic against
	// sessions they don't actually own.
	if strings.TrimSpace(deviceID) == "" {

		return errs.ErrInvalidRequest
	}

	if !deviceType.Valid() {

		return errs.ErrInvalidRequest
	}

	return nil

}
