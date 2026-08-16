package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	domainToken "github.com/papanazz/auth-service-v2/internal/domain/token"
)

var _ domainToken.AccessTokenService = (*JWTService)(nil)

type JWTService struct {
	secret []byte

	ttl time.Duration
}

func NewJWTService(
	secret string,
	ttl time.Duration,
) *JWTService {

	return &JWTService{

		secret: []byte(secret),

		ttl: ttl,
	}
}

type claims struct {

	// Subject
	//
	// Represents authenticated user.
	//
	UserID string `json:"sub"`

	// Authentication session identifier.
	//
	// Allows tracing:
	//
	// User
	//   |
	//   +-- Session
	//          |
	//          +-- Access Token
	//
	SessionID string `json:"sid"`

	jwt.RegisteredClaims
}

func (s *JWTService) Generate(
	input domainToken.Claims,
) (
	domainToken.AccessToken,
	error,
) {

	now :=
		time.Now().
			UTC()

	expiration :=
		now.Add(
			s.ttl,
		)

	token :=
		jwt.NewWithClaims(

			jwt.SigningMethodHS256,

			claims{

				UserID: input.UserID.String(),

				SessionID: input.SessionID.String(),

				RegisteredClaims: jwt.RegisteredClaims{

					ExpiresAt: jwt.NewNumericDate(
						expiration,
					),

					IssuedAt: jwt.NewNumericDate(
						now,
					),

					NotBefore: jwt.NewNumericDate(
						now,
					),
				},
			},
		)

	signed, err :=
		token.SignedString(
			s.secret,
		)

	if err != nil {

		return domainToken.AccessToken{},
			fmt.Errorf("sign access token: %w", err)
	}

	return domainToken.AccessToken{

		Token: signed,

		ExpiresAt: expiration,
	}, nil

}
