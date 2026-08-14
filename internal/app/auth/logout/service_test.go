package logout

import (
	"context"
	"errors"
	"testing"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	domainRefresh "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func TestService_Handle_Success(t *testing.T) {

	h := newHarness()

	err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.sessions.revocationCount() != 1 {
		t.Fatalf("sessions revoked = %d, want 1", h.sessions.revocationCount())
	}

	if h.sessions.revokedSessions[0] != session.RevokeUserLogout {
		t.Errorf("session revoke reason = %v, want %v", h.sessions.revokedSessions[0], session.RevokeUserLogout)
	}

	if h.refreshTokens.revocationCount() != 1 {
		t.Fatalf("refresh token families revoked = %d, want 1", h.refreshTokens.revocationCount())
	}

	if h.refreshTokens.revokedFamilies[0] != domainRefresh.RevokeReasonLogout {
		t.Errorf("family revoke reason = %v, want %v", h.refreshTokens.revokedFamilies[0], domainRefresh.RevokeReasonLogout)
	}

	if got := h.audit.countOf(audit.EventLogout, true); got != 1 {
		t.Errorf("successful LOGOUT audit events = %d, want 1", got)
	}
}

// Logging out twice (e.g. a double-tap, or an app calling logout on teardown
// after the user already logged out) must not surface as an error — the end
// state the caller wants is already true.
func TestService_Handle_IdempotentOnAlreadyRevokedSession(t *testing.T) {

	h := newHarness()

	if err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	); err != nil {
		t.Fatalf("first logout failed: %v", err)
	}

	if err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	); err != nil {
		t.Fatalf("second logout failed: %v", err)
	}

	if h.sessions.revocationCount() != 2 {
		t.Errorf("session revoke calls = %d, want 2", h.sessions.revocationCount())
	}
}

func TestService_Handle_Rejections(t *testing.T) {

	tests := []struct {
		name string

		setup func(h *harness) Command

		wantErr error
	}{
		{
			name: "rejects an unknown token",

			setup: func(h *harness) Command {
				return Command{RefreshToken: "never-issued"}
			},

			wantErr: errs.ErrInvalidRefreshToken,
		},
		{
			name: "rejects a token whose session is gone",

			setup: func(h *harness) Command {
				delete(h.sessions.stored, h.session.ID)
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errs.ErrInvalidRefreshToken,
		},
		{
			name: "propagates a transaction failure",

			setup: func(h *harness) Command {
				h.transaction.err = errBackendDown
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errBackendDown,
		},
		{
			name: "propagates a session revoke failure",

			setup: func(h *harness) Command {
				h.sessions.revokeErr = errBackendDown
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errBackendDown,
		},
		{
			name: "propagates a family revoke failure",

			setup: func(h *harness) Command {
				h.refreshTokens.revokeFamilyErr = errBackendDown
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errBackendDown,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			h := newHarness()

			cmd := tt.setup(h)

			err := h.service().Handle(
				context.Background(),
				cmd,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
