package refresh_token

type Hasher interface {
	Hash(
		value string,
	) string
}
