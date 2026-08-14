package verification

import (
	"crypto/rand"
	"encoding/base64"

	domain "github.com/papanazz/auth-service-v2/internal/domain/verification"
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
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
