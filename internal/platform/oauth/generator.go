package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	domain "github.com/papanazz/auth-service-v2/internal/domain/oauth"
)

var _ domain.Generator = (*RandomGenerator)(nil)

type RandomGenerator struct{}

func NewRandomGenerator() *RandomGenerator {

	return &RandomGenerator{}
}

func (g *RandomGenerator) GenerateState() (
	string,
	error,
) {

	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GeneratePKCE follows RFC 7636's S256 method: verifier is 32 random
// bytes base64url-encoded (43 characters — exactly the spec's minimum
// length), challenge is the base64url-encoded SHA-256 of the verifier's
// ASCII bytes.
func (g *RandomGenerator) GeneratePKCE() (
	string,
	string,
	error,
) {

	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("generate pkce verifier: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(bytes)

	sum := sha256.Sum256([]byte(verifier))

	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	return verifier, challenge, nil
}
