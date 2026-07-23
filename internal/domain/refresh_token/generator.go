package refresh_token

type Generator interface {
	Generate() (
		string,
		error,
	)
}
