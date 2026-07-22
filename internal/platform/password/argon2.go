package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2id struct {
	memory uint32

	iterations uint32

	parallelism uint8

	saltLength uint32

	keyLength uint32
}

func NewArgon2id() *Argon2id {

	return &Argon2id{

		memory: 64 * 1024,

		iterations: 3,

		parallelism: 2,

		saltLength: 16,

		keyLength: 32,
	}
}

func (a *Argon2id) Hash(
	password string,
) (
	string,
	error,
) {

	salt :=
		make([]byte, a.saltLength)

	_, err :=
		rand.Read(salt)

	if err != nil {
		return "", err
	}

	hash :=
		argon2.IDKey(

			[]byte(password),

			salt,

			a.iterations,

			a.memory,

			a.parallelism,

			a.keyLength,
		)

	return fmt.Sprintf(

		"argon2id$%d$%d$%d$%s$%s",

		a.memory,

		a.iterations,

		a.parallelism,

		base64.RawStdEncoding.EncodeToString(salt),

		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func (a *Argon2id) Compare(
	stored string,
	password string,
) error {

	parts := strings.Split(
		stored,
		"$",
	)

	if len(parts) != 6 {
		return errors.New(
			"invalid password hash format",
		)
	}

	if parts[0] != "argon2id" {
		return errors.New(
			"unsupported password hash algorithm",
		)
	}

	memory, err :=
		strconv.ParseUint(
			parts[1],
			10,
			32,
		)

	if err != nil {
		return errors.New(
			"invalid memory parameter",
		)
	}

	iterations, err :=
		strconv.ParseUint(
			parts[2],
			10,
			32,
		)

	if err != nil {
		return errors.New(
			"invalid iteration parameter",
		)
	}

	parallelism, err :=
		strconv.ParseUint(
			parts[3],
			10,
			8,
		)

	if err != nil {
		return errors.New(
			"invalid parallelism parameter",
		)
	}

	salt, err :=
		base64.RawStdEncoding.DecodeString(
			parts[4],
		)

	if err != nil {
		return errors.New(
			"invalid salt",
		)
	}

	expectedHash, err :=
		base64.RawStdEncoding.DecodeString(
			parts[5],
		)

	if err != nil {
		return errors.New(
			"invalid hash",
		)
	}

	actualHash :=
		argon2.IDKey(

			[]byte(password),

			salt,

			uint32(iterations),

			uint32(memory),

			uint8(parallelism),

			uint32(len(expectedHash)),
		)

	if subtle.ConstantTimeCompare(
		actualHash,
		expectedHash,
	) != 1 {

		return errors.New(
			"invalid password",
		)
	}

	return nil
}
