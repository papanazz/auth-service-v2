package logger

import "strings"

// MaskEmail partially redacts an email address for logging: enough of
// the local part survives to eyeball- or grep-match a specific known
// account, without putting the full address in plaintext into a log
// stream that may have wider retention and broader access than the
// database column it's also stored in unmasked.
func MaskEmail(
	email string,
) string {

	at := strings.LastIndex(email, "@")

	if at <= 0 {
		return "***"
	}

	local := email[:at]

	domain := email[at:]

	// at > 0 guarantees local is at least 1 character here.
	if len(local) == 1 {
		return local[:1] + "***" + domain
	}

	return local[:2] + "***" + domain
}
