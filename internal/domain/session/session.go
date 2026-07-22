package session

import (
	"time"

	"github.com/google/uuid"
)

type DeviceType string

const (
	DeviceAndroid DeviceType = "ANDROID"
	DeviceIOS     DeviceType = "IOS"
	DeviceWEB     DeviceType = "WEB"
)

type Session struct {
	ID uuid.UUID

	UserID uuid.UUID

	DeviceID string

	DeviceName string

	DeviceType DeviceType

	UserAgent string

	IpAddress string

	LastUsedAt *time.Time

	RevokedAt *time.Time

	CreatedAt time.Time

	UpdatedAt time.Time
}
