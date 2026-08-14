package verification

type Generator interface {
	Generate() (
		string,
		error,
	)
}
