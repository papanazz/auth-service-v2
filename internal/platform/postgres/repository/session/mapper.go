package session

import (
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	domain "github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

func mapCreateParams(
	input domain.Session,
) sqlc.CreateSessionParams {

	return sqlc.CreateSessionParams{

		ID: input.ID,

		UserID: input.UserID,

		DeviceID: input.DeviceID,

		DeviceName: stringPointer(
			input.DeviceName,
		),

		DeviceType: sqlc.DeviceType(
			input.DeviceType,
		),

		UserAgent: textValue(
			input.UserAgent,
		),

		IpAddress: nil,

		LastUsedAt: timeToTimestamptz(
			input.LastUsedAt,
		),
	}
}

func mapSession(
	row sqlc.Session,
) *domain.Session {

	return &domain.Session{

		ID: row.ID,

		UserID: row.UserID,

		DeviceID: row.DeviceID,

		DeviceName: stringValue(
			row.DeviceName,
		),

		DeviceType: domain.DeviceType(
			row.DeviceType,
		),

		UserAgent: textString(
			row.UserAgent,
		),

		IPAddress: ipString(
			row.IpAddress,
		),

		LastUsedAt: timestampValue(
			row.LastUsedAt,
		),

		RevokedAt: timestampValue(
			row.RevokedAt,
		),

		CreatedAt: row.CreatedAt.Time,

		UpdatedAt: row.UpdatedAt.Time,
	}
}

func stringPointer(
	value string,
) *string {

	if value == "" {
		return nil
	}

	return &value
}

func stringValue(
	value *string,
) string {

	if value == nil {
		return ""
	}

	return *value
}

func textValue(
	value string,
) pgtype.Text {

	if value == "" {
		return pgtype.Text{
			Valid: false,
		}
	}

	return pgtype.Text{
		String: value,
		Valid:  true,
	}
}

func textString(
	value pgtype.Text,
) string {

	if !value.Valid {
		return ""
	}

	return value.String
}

func timeToTimestamptz(
	value *time.Time,
) pgtype.Timestamptz {

	if value == nil {
		return pgtype.Timestamptz{
			Valid: false,
		}
	}

	return pgtype.Timestamptz{
		Time:  *value,
		Valid: true,
	}
}

func timestampValue(
	value pgtype.Timestamptz,
) *time.Time {

	if !value.Valid {
		return nil
	}

	return &value.Time
}

func ipString(
	value *netip.Addr,
) string {

	if value == nil {
		return ""
	}

	return value.String()
}
