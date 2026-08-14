package response

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
)

// StatusForError resolves the HTTP status err maps to, without writing
// anything — the one place this mapping lives, shared by WriteError and
// LogAndWriteError so the status a client sees and the severity a log
// line is recorded at can never disagree with each other.
func StatusForError(
	err error,
) int {

	appErr, ok := err.(*errs.Error)

	if !ok {
		return http.StatusInternalServerError
	}

	switch appErr.Code {

	case errs.CodeInvalidRequest,
		errs.CodeInvalidEmail,
		errs.CodeWeakPassword,
		errs.CodeIdempotencyKeyRequired,
		errs.CodeInvalidVerificationToken:

		return http.StatusBadRequest

	case errs.CodeUserAlreadyExists:

		return http.StatusConflict

	case errs.CodeUserNotFound:

		return http.StatusNotFound

	case errs.CodeInvalidCredentials,
		errs.CodeInvalidRefreshToken,
		errs.CodeRefreshTokenReplay:

		// A replayed token is an authentication failure, not a server
		// fault. Returning 500 would both mislead the client and page
		// an on-call engineer for what is a client-side event.
		return http.StatusUnauthorized

	case errs.CodeEmailNotVerified,
		errs.CodeAccountLocked:

		return http.StatusForbidden

	case errs.CodeTooManyRequest:

		return http.StatusTooManyRequests

	case errs.CodeDeviceSessionActive,
		errs.CodeIdempotencyKeyInProgress,
		errs.CodeIdempotencyKeyConflict:

		return http.StatusConflict
	}

	return http.StatusInternalServerError
}

func WriteError(
	w http.ResponseWriter,
	err error,
) {

	if appErr, ok := err.(*errs.Error); ok {

		w.Header().Set(
			"Content-Type",
			"application/json",
		)

		w.WriteHeader(
			StatusForError(err),
		)

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

// levelLogger is the slice of *logger.Logger's method set LogAndWriteError
// actually needs — narrow on purpose so a test can supply a recording
// fake without reaching into zap's own output.
type levelLogger interface {
	Warn(ctx context.Context, message string, metadata logger.Metadata)

	Error(ctx context.Context, message string, err error, metadata logger.Metadata)
}

// LogAndWriteError logs err at a severity derived from the HTTP status
// it resolves to, then writes the error response. The two happen
// together deliberately: logging and responding as two separate calls
// let a handler drift — logging one severity while a different status
// went out on the wire — and every handler in this codebase used to do
// exactly that (see docs/logging.md).
//
// Warn for 4xx: expected, client-caused, and often high-volume by
// design (wrong passwords, rate limiting, an already-used verification
// token) — logging these at Error would drown a real incident in noise.
// Error for 5xx: something this service didn't expect, worth alerting
// on.
//
// metadata is mutated: error_code is always added from err when it's an
// *errs.Error, and on the Warn path err.Error() is added as error too
// (the Error-level path already gets this from zap.Error via Logger.Error).
// Callers should only ever put already-safe values in — see
// logger.MaskEmail for the one PII field these handlers currently pass
// through it — never a password or a raw token; see docs/logging.md
// Decisions for why those two classes are excluded even from the
// Error-level path.
func LogAndWriteError(
	w http.ResponseWriter,
	ctx context.Context,
	log levelLogger,
	operation string,
	err error,
	metadata logger.Metadata,
) {

	status := StatusForError(err)

	if metadata == nil {
		metadata = logger.Metadata{}
	}

	if appErr, ok := err.(*errs.Error); ok {
		metadata["error_code"] = string(appErr.Code)
	}

	message := "[" + operation + "] request failed"

	if status >= http.StatusInternalServerError {

		log.Error(ctx, message, err, metadata)

	} else {

		metadata["error"] = err.Error()

		log.Warn(ctx, message, metadata)
	}

	WriteError(w, err)
}
