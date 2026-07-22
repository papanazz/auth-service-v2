package token

type RefreshTokenGenerator interface {
	Generate() (
		string,
		error,
	)
}
