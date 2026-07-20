package password

import (
	"golang.org/x/crypto/bcrypt"
)

type Bcrypt struct{}

func NewBcrypt() *Bcrypt {

	return &Bcrypt{}

}

func (b *Bcrypt) Hash(
	password string,
) (
	string,
	error,
) {

	result, err :=
		bcrypt.GenerateFromPassword(
			[]byte(password),
			bcrypt.DefaultCost,
		)

	return string(result), err

}

func (b *Bcrypt) Compare(
	hash string,
	password string,
) error {

	return bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	)

}
