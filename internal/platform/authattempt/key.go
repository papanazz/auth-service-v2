package authattempt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
)

func LoginIP(
	ip string,
) string {

	return fmt.Sprintf(
		"auth:login:ip:%s",
		normalizeIP(ip),
	)
}

func RegisterIP(
	ip string,
) string {

	return fmt.Sprintf(
		"auth:register:ip:%s",
		normalizeIP(ip),
	)
}

func ResendVerificationIP(
	ip string,
) string {

	return fmt.Sprintf(
		"auth:resend-verification:ip:%s",
		normalizeIP(ip),
	)
}

func LoginCredential(
	email string,
	ip string,
) string {

	hash :=
		sha256.Sum256(
			[]byte(
				email +
					":" +
					normalizeIP(ip),
			),
		)

	return fmt.Sprintf(
		"auth:login:credential:%s",
		hex.EncodeToString(
			hash[:],
		),
	)
}

// normalizeIP strips the port from http.Request.RemoteAddr before it goes
// into a rate-limit key.
//
// Without this, every connection from the same client — a new ephemeral
// source port each time — produces a distinct key, so the sliding window
// never accumulates and the limiter never trips. Mirrors the identical
// fix already applied to the session and audit repositories' own address
// parsing (see their parseIP, particularly session's TestParseIP for the
// original regression this pattern guards against); this is the same bug
// in a third place it was never ported to.
func normalizeIP(
	value string,
) string {

	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}

	return value
}
