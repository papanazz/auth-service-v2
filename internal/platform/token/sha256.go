package token

import (
	"crypto/sha256"
	"encoding/hex"

	domainToken "github.com/papanazz/auth-service-v2/internal/domain/token"
)

var _ domainToken.Hasher = (*SHA256Hasher)(nil)

type SHA256Hasher struct{}

func NewSHA256Hasher() *SHA256Hasher {

	return &SHA256Hasher{}

}

func (h *SHA256Hasher) Hash(
	value string,
) string {

	sum :=
		sha256.Sum256(
			[]byte(value),
		)

	return hex.EncodeToString(
		sum[:],
	)

}
