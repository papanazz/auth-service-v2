package refresh_token

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	domain "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
)

var _ domain.Generator = (*RandomGenerator)(nil)

type RandomGenerator struct{}

func NewRandomGenerator() *RandomGenerator {

	return &RandomGenerator{}

}

func (g *RandomGenerator) Generate() (string, error) {

	bytes :=
		make([]byte, 32)

	_, err :=
		rand.Read(bytes)

	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
