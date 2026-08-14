package response

import (
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func WriteError(
	w http.ResponseWriter,
	err error,
) {
	if appErr, ok := err.(*errs.Error); ok {

		status := http.StatusInternalServerError

		switch appErr.Code {

		case errs.CodeInvalidRequest,
			errs.CodeInvalidEmail,
			errs.CodeWeakPassword,
			errs.CodeIdempotencyKeyRequired:

			status = http.StatusBadRequest

		case errs.CodeUserAlreadyExists:

			status = http.StatusConflict

		case errs.CodeUserNotFound:

			status = http.StatusNotFound

		case errs.CodeInvalidCredentials,
			errs.CodeInvalidRefreshToken,
			errs.CodeRefreshTokenReplay:

			// A replayed token is an authentication failure, not a server
			// fault. Returning 500 would both mislead the client and page
			// an on-call engineer for what is a client-side event.
			status = http.StatusUnauthorized

		case errs.CodeEmailNotVerified,
			errs.CodeAccountLocked:

			status = http.StatusForbidden

		case errs.CodeTooManyRequest:

			status = http.StatusTooManyRequests

		case errs.CodeDeviceSessionActive,
			errs.CodeIdempotencyKeyInProgress,
			errs.CodeIdempotencyKeyConflict:

			status = http.StatusConflict
		}

		w.Header().Set(
			"Content-Type",
			"application/json",
		)

		w.WriteHeader(status)

		_ = json.NewEncoder(w).Encode(
			Response{
				Error: &ErrorResponse{
					Code:    string(appErr.Code),
					Message: appErr.Message,
				},
			},
		)

		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(http.StatusInternalServerError)

	_ = json.NewEncoder(w).Encode(
		Response{
			Error: &ErrorResponse{
				Code:    string(errs.CodeInternal),
				Message: "internal server errs",
			},
		},
	)
}
