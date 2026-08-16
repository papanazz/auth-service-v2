package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	domain "github.com/papanazz/auth-service-v2/internal/domain/password"
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
		make(
			[]byte,
			a.saltLength,
		)

	_, err :=
		rand.Read(
			salt,
		)

	if err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
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

		base64.RawStdEncoding.EncodeToString(
			salt,
		),

		base64.RawStdEncoding.EncodeToString(
			hash,
		),
	), nil
}

func (a *Argon2id) Verify(
	storedHash string,
	password string,
) error {

	parts :=
		strings.Split(
			storedHash,
			"$",
		)

	if len(parts) != 6 {

		return domain.ErrInvalidHash
	}

	if parts[0] != "argon2id" {

		return domain.ErrInvalidHash
	}

	memory, err :=
		strconv.ParseUint(
			parts[1],
			10,
			32,
		)

	if err != nil {

		return domain.ErrInvalidHash
	}

	iterations, err :=
		strconv.ParseUint(
			parts[2],
			10,
			32,
		)

	if err != nil {

		return domain.ErrInvalidHash
	}

	parallelism, err :=
		strconv.ParseUint(
			parts[3],
			10,
			8,
		)

	if err != nil {

		return domain.ErrInvalidHash
	}

	salt, err :=
		base64.RawStdEncoding.DecodeString(
			parts[4],
		)

	if err != nil {

		return domain.ErrInvalidHash
	}

	expectedHash, err :=
		base64.RawStdEncoding.DecodeString(
			parts[5],
		)

	if err != nil {

		return domain.ErrInvalidHash
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

		return domain.ErrInvalidPassword
	}

	return nil
}
