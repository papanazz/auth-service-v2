package session

import (
	"net"
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

		IpAddress: parseIP(
			input.IPAddress,
		),

		LastUsedAt: timeToTimestamptz(
			input.LastUsedAt,
		),

		ExpiresAt: timeToTimestamptz(
			&input.ExpiresAt,
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

		LastRefreshedAt: timestampValue(
			row.LastRefreshedAt,
		),

		ExpiresAt: row.ExpiresAt.Time,

		RevokedAt: timestampValue(
			row.RevokedAt,
		),

		RevokedReason: revokeReason(
			row.RevokedReason,
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

// parseIP converts the client address into the INET value the column expects.
//
// The transport layer supplies http.Request.RemoteAddr, which carries a port
// ("203.0.113.10:54321", or "[2001:db8::1]:54321" for IPv6). netip.ParseAddr
// rejects that form, so the port is stripped first.
//
// An unparseable address is stored as NULL rather than failing the login: the
// address is diagnostic metadata, not an authentication input.
func parseIP(
	value string,
) *netip.Addr {

	if value == "" {
		return nil
	}

	candidate := value

	if host, _, err := net.SplitHostPort(value); err == nil {
		candidate = host
	}

	addr, err := netip.ParseAddr(candidate)

	if err != nil {
		return nil
	}

	return &addr
}

func revokeReason(
	value *string,
) *domain.RevokeReason {

	if value == nil {
		return nil
	}

	reason := domain.RevokeReason(*value)

	return &reason
}
