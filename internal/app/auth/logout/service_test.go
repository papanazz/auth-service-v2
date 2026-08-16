package logout

import (
	"context"
	"errors"
	"sync"
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

// The audit trail must carry the same client context login/refresh's does,
// and the right session/user — not attributed to the wrong identifier the
// way refresh's once was (see docs/refresh.md).
func TestService_Handle_AuditEventCarriesContext(t *testing.T) {

	h := newHarness()

	err := h.service().Handle(
		context.Background(),
		Command{
			RefreshToken: h.rawToken,
			IPAddress:    "203.0.113.10",
			UserAgent:    "Mozilla/5.0",
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(h.audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(h.audit.events))
	}

	event := h.audit.events[0]

	if event.UserID == nil || *event.UserID != h.session.UserID {
		t.Errorf("event user ID = %v, want %v", event.UserID, h.session.UserID)
	}

	if event.SessionID == nil || *event.SessionID != h.session.ID {
		t.Errorf("event session ID = %v, want %v", event.SessionID, h.session.ID)
	}

	if event.IPAddress != "203.0.113.10" {
		t.Errorf("event IP = %q, want %q", event.IPAddress, "203.0.113.10")
	}

	if event.UserAgent != "Mozilla/5.0" {
		t.Errorf("event user agent = %q, want %q", event.UserAgent, "Mozilla/5.0")
	}
}

// The centerpiece: N clients racing to log out the same session at once —
// e.g. multiple tabs, or a client retrying after a timeout. Every caller
// must succeed; logout is a destructive, idempotent operation, so unlike
// refresh there is no "exactly one winner" — everyone gets the end state
// they asked for.
func TestService_Handle_ConcurrentLogoutsAllSucceed(t *testing.T) {

	const clients = 20

	h := newHarness()

	service := h.service()

	var (
		wg sync.WaitGroup

		mu sync.Mutex

		failures []error
	)

	start := make(chan struct{})

	for i := 0; i < clients; i++ {

		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			err := service.Handle(
				context.Background(),
				Command{RefreshToken: h.rawToken},
			)

			if err != nil {

				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}()
	}

	close(start)
	wg.Wait()

	if len(failures) != 0 {
		t.Fatalf("%d/%d concurrent logouts failed: %v", len(failures), clients, failures)
	}

	if got := h.audit.countOf(audit.EventLogout, true); got != clients {
		t.Errorf("successful LOGOUT audit events = %d, want %d — every caller succeeded", got, clients)
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
			// A genuine repository failure must not be conflated with
			// "unknown token" — see docs/logging.md.
			name: "propagates a genuine token lookup failure unmasked",

			setup: func(h *harness) Command {
				h.refreshTokens.findErr = errBackendDown
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errBackendDown,
		},
		{
			name: "propagates a genuine session lookup failure unmasked",

			setup: func(h *harness) Command {
				h.sessions.findErr = errBackendDown
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errBackendDown,
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
