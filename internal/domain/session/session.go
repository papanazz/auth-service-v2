package session

import (
	"time"

	"github.com/google/uuid"
)

type DeviceType string

const (
	DeviceAndroid DeviceType = "ANDROID"
	DeviceIOS     DeviceType = "IOS"
	DeviceWeb     DeviceType = "WEB"
)

type RevokeReason string

const (
	RevokeUserLogout         RevokeReason = "USER_LOGOUT"
	RevokePasswordChanged    RevokeReason = "PASSWORD_CHANGED"
	RevokeAdminAction        RevokeReason = "ADMIN_ACTION"
	RevokeTokenReuseDetected RevokeReason = "TOKEN_REUSE_DETECTED"

	// RevokeSessionSuperseded marks a session killed by a fresh login from the
	// same device within the login grace period — treated as the same client
	// retrying (e.g. after a network timeout) rather than a new session.
	RevokeSessionSuperseded RevokeReason = "SESSION_SUPERSEDED"
)

type Session struct {
	ID uuid.UUID

	UserID uuid.UUID

	DeviceID   string
	DeviceName string
	DeviceType DeviceType

	UserAgent string
	IPAddress string

	LastUsedAt      *time.Time
	LastRefreshedAt *time.Time

	ExpiresAt time.Time

	RevokedAt     *time.Time
	RevokedReason *RevokeReason

	CreatedAt time.Time
	UpdatedAt time.Time
}

func New(
	userID uuid.UUID,
	deviceID string,
	deviceName string,
	deviceType DeviceType,
	userAgent string,
	ipAddress string,
	expiresAt time.Time,
) Session {

	now := time.Now().UTC()

	return Session{
		ID: uuid.New(),

		UserID: userID,

		DeviceID:   deviceID,
		DeviceName: deviceName,
		DeviceType: deviceType,

		UserAgent: userAgent,
		IPAddress: ipAddress,

		LastUsedAt: &now,

		ExpiresAt: expiresAt,

		CreatedAt: now,
		UpdatedAt: now,
	}
}

func (s Session) IsExpired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

func (s Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

func (s Session) IsActive(now time.Time) bool {
	return !s.IsRevoked() && !s.IsExpired(now)
}

func (s *Session) Touch(now time.Time) {

	if !s.IsActive(now) {
		return
	}

	s.LastUsedAt = &now
	s.UpdatedAt = now
}

func (s *Session) Refresh(now time.Time) {

	if !s.IsActive(now) {
		return
	}

	s.LastRefreshedAt = &now
	s.LastUsedAt = &now
	s.UpdatedAt = now
}

func (s *Session) Revoke(
	now time.Time,
	reason RevokeReason,
) {

	if s.RevokedAt != nil {
		return
	}

	s.RevokedAt = &now
	s.RevokedReason = &reason
	s.UpdatedAt = now
}
