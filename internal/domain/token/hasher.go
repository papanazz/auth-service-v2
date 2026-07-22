package token

type Hasher interface {
	Hash(
		value string,
	) string
}
