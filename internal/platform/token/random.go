package token

import (
	"crypto/rand"
	"encoding/base64"

	refresh "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
)

var _ refresh.Generator = (*RandomGenerator)(nil)

type RandomGenerator struct{}

func NewRandomGenerator() *RandomGenerator {

	return &RandomGenerator{}

}

func (g *RandomGenerator) Generate() (
	string,
	error,
) {

	bytes :=
		make([]byte, 32)

	_, err :=
		rand.Read(bytes)

	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
