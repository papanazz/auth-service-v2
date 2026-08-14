package user

import (
	"time"

	"github.com/google/uuid"
)

type Status string

const (
	StatusPending Status = "PENDING"

	StatusActive Status = "ACTIVE"

	StatusSuspended Status = "SUSPENDED"

	StatusLocked Status = "LOCKED"

	StatusDeleted Status = "DELETED"
)

type User struct {
	ID uuid.UUID

	Email string

	PasswordHash string

	Status Status

	EmailVerifiedAt *time.Time

	LastLoginAt *time.Time

	FailedLoginAttempts int

	LockedUntil *time.Time

	CreatedAt time.Time

	UpdatedAt time.Time
}

func New(
	email string,
	passwordHash string,
) User {

	now := time.Now().UTC()

	return User{

		ID: uuid.New(),

		Email: NormalizeEmail(email),

		PasswordHash: passwordHash,

		Status: StatusPending,

		CreatedAt: now,

		UpdatedAt: now,
	}
}

func (u User) CanLogin(
	now time.Time,
) bool {

	if u.Status != StatusActive {
		return false
	}

	if u.LockedUntil != nil &&
		now.Before(*u.LockedUntil) {

		return false
	}

	return true
}

func (u *User) VerifyEmail(
	now time.Time,
) {

	u.EmailVerifiedAt = &now

	if u.Status == StatusPending {
		u.Status = StatusActive
	}

	u.UpdatedAt = now
}

func (u *User) RecordSuccessfulLogin(
	now time.Time,
) {

	u.LastLoginAt = &now

	u.FailedLoginAttempts = 0

	u.LockedUntil = nil

	u.UpdatedAt = now
}

func (u *User) RecordFailedLogin(
	now time.Time,
	maxAttempts int,
	lockDuration time.Duration,
) {

	u.FailedLoginAttempts++

	if u.FailedLoginAttempts >= maxAttempts {

		lockUntil := now.Add(lockDuration)

		u.LockedUntil = &lockUntil

		u.Status = StatusLocked
	}

	u.UpdatedAt = now
}

func (u *User) Unlock(
	now time.Time,
) {

	u.Status = StatusActive

	u.FailedLoginAttempts = 0

	u.LockedUntil = nil

	u.UpdatedAt = now
}

func (u *User) Suspend(
	now time.Time,
) {

	u.Status = StatusSuspended

	u.UpdatedAt = now
}
