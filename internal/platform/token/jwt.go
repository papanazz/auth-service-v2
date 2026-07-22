package token

import (
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
	UserID string `json:"sub"`

	jwt.RegisteredClaims
}

func (s *JWTService) Generate(
	input domainToken.Claims,
) (
	domainToken.AccessToken,
	error,
) {

	expiration :=
		time.Now().
			Add(
				s.ttl,
			)

	token :=
		jwt.NewWithClaims(
			jwt.SigningMethodHS256,

			claims{

				UserID: input.UserID.String(),

				RegisteredClaims: jwt.RegisteredClaims{

					ExpiresAt: jwt.NewNumericDate(
						expiration,
					),

					IssuedAt: jwt.NewNumericDate(
						time.Now(),
					),
				},
			},
		)

	signed, err :=
		token.SignedString(
			s.secret,
		)

	if err != nil {

		return domainToken.AccessToken{}, err

	}

	return domainToken.AccessToken{

		Token: signed,

		ExpiresAt: expiration,
	}, nil

}
