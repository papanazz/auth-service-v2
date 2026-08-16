package oauthcallback

import (
	"strings"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func Validate(
	code string,
	state string,
) error {

	if strings.TrimSpace(code) == "" {

		return errs.ErrInvalidRequest
	}

	if strings.TrimSpace(state) == "" {

		return errs.ErrInvalidRequest
	}

	return nil
}
