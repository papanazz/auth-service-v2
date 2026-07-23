package audit

import (
	"time"

	"github.com/google/uuid"
)

type Event struct {
	ID uuid.UUID

	Type string

	UserID uuid.UUID

	Email string

	IpAddress string

	UserAgent string

	Success bool

	Reason string

	Metadata map[string]any

	CreatedAt time.Time
}
