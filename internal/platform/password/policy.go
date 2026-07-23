package password

import (
	"unicode"

	domain "github.com/papanazz/auth-service-v2/internal/domain/password"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

var _ domain.Policy = (*Policy)(nil)

type Policy struct {
	minLength int
}

func NewPolicy() *Policy {

	return &Policy{

		minLength: 8,
	}

}

func (p *Policy) Validate(
	password string,
) error {

	if len(password) < p.minLength {

		return errs.ErrWeakPassword
	}

	var (
		hasUpper bool

		hasLower bool

		hasDigit bool
	)

	for _, r := range password {

		switch {

		case unicode.IsUpper(r):

			hasUpper = true

		case unicode.IsLower(r):

			hasLower = true

		case unicode.IsDigit(r):

			hasDigit = true

		}

	}

	if !hasUpper ||
		!hasLower ||
		!hasDigit {

		return errs.ErrWeakPassword
	}

	return nil
}
