package password

type Repository interface {
	Hash(password string) (string, error)
	Compare(hash string, password string) error
}
