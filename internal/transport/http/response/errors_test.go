package response

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
)

type loggedCall struct {
	level string

	message string

	err error

	metadata logger.Metadata
}

type mockLogger struct {
	calls []loggedCall
}

func (m *mockLogger) Warn(
	ctx context.Context,
	message string,
	metadata logger.Metadata,
) {

	m.calls = append(m.calls, loggedCall{
		level: "warn",

		message: message,

		metadata: metadata,
	})
}

func (m *mockLogger) Error(
	ctx context.Context,
	message string,
	err error,
	metadata logger.Metadata,
) {

	m.calls = append(m.calls, loggedCall{
		level: "error",

		message: message,

		err: err,

		metadata: metadata,
	})
}

func TestStatusForError(t *testing.T) {

	tests := []struct {
		name string

		err error

		want int
	}{
		{"invalid request", errs.ErrInvalidRequest, http.StatusBadRequest},
		{"invalid verification token", errs.ErrInvalidVerificationToken, http.StatusBadRequest},
		{"user already exists", errs.ErrUserAlreadyExists, http.StatusConflict},
		{"user not found", errs.ErrUserNotFound, http.StatusNotFound},
		{"invalid credentials", errs.ErrInvalidCredentials, http.StatusUnauthorized},
		{"refresh token replay", errs.ErrRefreshTokenReplay, http.StatusUnauthorized},
		{"account locked", errs.ErrAccountLocked, http.StatusForbidden},
		{"too many requests", errs.ErrTooManyRequests, http.StatusTooManyRequests},
		{"device session active", errs.ErrDeviceSessionActive, http.StatusConflict},
		{"a raw, unmapped error", errors.New("connection refused"), http.StatusInternalServerError},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			if got := StatusForError(tt.err); got != tt.want {
				t.Errorf("StatusForError(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestLogAndWriteError_FourXXLogsAtWarn(t *testing.T) {

	log := &mockLogger{}

	rec := httptest.NewRecorder()

	LogAndWriteError(rec, context.Background(), log, "Login", errs.ErrInvalidCredentials, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	if len(log.calls) != 1 {
		t.Fatalf("logged %d calls, want 1", len(log.calls))
	}

	if log.calls[0].level != "warn" {
		t.Errorf("logged at %q, want %q — a 401 is a routine client error, not an incident", log.calls[0].level, "warn")
	}
}

func TestLogAndWriteError_FiveXXLogsAtError(t *testing.T) {

	log := &mockLogger{}

	rec := httptest.NewRecorder()

	backendErr := errors.New("dial tcp: connection refused")

	LogAndWriteError(rec, context.Background(), log, "Login", backendErr, nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	if len(log.calls) != 1 {
		t.Fatalf("logged %d calls, want 1", len(log.calls))
	}

	if log.calls[0].level != "error" {
		t.Errorf("logged at %q, want %q — an unmapped error is a real failure", log.calls[0].level, "error")
	}

	if log.calls[0].err != backendErr {
		t.Error("the Error-level call must carry the original error")
	}
}

func TestLogAndWriteError_AddsErrorCodeToMetadata(t *testing.T) {

	log := &mockLogger{}

	rec := httptest.NewRecorder()

	metadata := logger.Metadata{"email": "ba***@example.com"}

	LogAndWriteError(rec, context.Background(), log, "Login", errs.ErrAccountLocked, metadata)

	if got := log.calls[0].metadata["error_code"]; got != string(errs.CodeAccountLocked) {
		t.Errorf(`metadata["error_code"] = %v, want %q`, got, errs.CodeAccountLocked)
	}

	// The caller's own fields must survive alongside error_code, not be
	// replaced by it.
	if got := log.calls[0].metadata["email"]; got != "ba***@example.com" {
		t.Errorf(`metadata["email"] = %v, want it preserved`, got)
	}
}

func TestLogAndWriteError_WarnPathIncludesTheErrorMessage(t *testing.T) {

	log := &mockLogger{}

	rec := httptest.NewRecorder()

	LogAndWriteError(rec, context.Background(), log, "Login", errs.ErrInvalidCredentials, nil)

	if got := log.calls[0].metadata["error"]; got != errs.ErrInvalidCredentials.Message {
		t.Errorf(`metadata["error"] = %v, want %q — Warn has no err parameter, unlike Error`, got, errs.ErrInvalidCredentials.Message)
	}
}

func TestLogAndWriteError_NilMetadataDoesNotPanic(t *testing.T) {

	log := &mockLogger{}

	rec := httptest.NewRecorder()

	LogAndWriteError(rec, context.Background(), log, "Refresh", errs.ErrInvalidRefreshToken, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
