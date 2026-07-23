package password

type Verifier interface {
	Verify(
		hash string,
		password string,
	) error
}
