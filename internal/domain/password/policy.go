package password

type Policy interface {
	Validate(
		password string,
	) error
}
