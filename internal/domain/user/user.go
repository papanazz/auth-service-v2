package user

import (
	"time"

	"github.com/google/uuid"
)

type Status string

const (
	StatusActive Status = "ACTIVE"
)

type User struct {
	ID uuid.UUID

	Email string

	PasswordHash string

	Status Status

	EmailVerifiedAt *time.Time

	LastLoginAt *time.Time

	CreatedAt time.Time

	UpdatedAt time.Time
}
