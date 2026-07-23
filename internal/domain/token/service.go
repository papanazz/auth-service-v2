package token

type AccessTokenService interface {
	Generate(
		claims Claims,
	) (
		AccessToken,
		error,
	)
}
