package authattempt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func LoginIP(
	ip string,
) string {

	return fmt.Sprintf(
		"auth:login:ip:%s",
		ip,
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
					ip,
			),
		)

	return fmt.Sprintf(
		"auth:login:credential:%s",
		hex.EncodeToString(
			hash[:],
		),
	)
}
