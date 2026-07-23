package audit

import (
	"encoding/json"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"

	domain "github.com/papanazz/auth-service-v2/internal/domain/audit"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

func mapCreateParams(
	event domain.Event,
) sqlc.CreateAuthenticationEventParams {

	metadata, _ :=
		json.Marshal(
			event.Metadata,
		)

	return sqlc.CreateAuthenticationEventParams{

		ID: event.ID,

		Type: string(event.Type),

		UserID: event.UserID,

		Email: &event.Email,

		IpAddress: parseIP(
			event.IPAddress,
		),

		UserAgent: text(
			event.UserAgent,
		),

		Success: event.Success,

		Reason: event.Reason,

		Metadata: metadata,
	}
}

func parseIP(
	value string,
) *netip.Addr {

	if value == "" {
		return nil
	}

	ip, err :=
		netip.ParseAddr(
			value,
		)

	if err != nil {
		return nil
	}

	return &ip
}

func text(
	value string,
) pgtype.Text {

	if value == "" {

		return pgtype.Text{
			Valid: false,
		}

	}

	return pgtype.Text{

		String: value,

		Valid: true,
	}
}

func stringPtr(
	value string,
) *string {

	if value == "" {
		return nil
	}

	return &value
}
