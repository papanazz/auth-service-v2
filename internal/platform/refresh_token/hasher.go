package refresh_token

import (
	"crypto/sha256"
	"encoding/hex"

	domain "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
)

var _ domain.Hasher = (*SHA256Hasher)(nil)

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
