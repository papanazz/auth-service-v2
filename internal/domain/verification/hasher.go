package verification

type Hasher interface {
	Hash(
		value string,
	) string
}
