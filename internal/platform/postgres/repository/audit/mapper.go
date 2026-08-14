package audit

import (
	"encoding/json"
	"net"
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

		SessionID: event.SessionID,

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

// parseIP converts the client address into the INET value the column
// expects.
//
// The transport layer supplies http.Request.RemoteAddr, which carries a
// port ("203.0.113.10:54321", or "[2001:db8::1]:54321" for IPv6).
// netip.ParseAddr rejects that form, so the port is stripped first. Mirrors
// the identical fix in the session repository's mapper — see its
// TestParseIP for the regression this guards against: every event was
// silently stored with a NULL ip_address despite the value being collected
// correctly.
//
// An unparseable address is stored as NULL rather than failing the
// request: the address is diagnostic metadata, not an authentication
// input.
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

	addr, err :=
		netip.ParseAddr(
			candidate,
		)

	if err != nil {
		return nil
	}

	return &addr
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
