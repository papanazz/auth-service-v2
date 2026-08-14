package verifyemail

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func TestService_Handle_Success(t *testing.T) {

	h := newHarness()

	result, err := h.service().Handle(
		context.Background(),
		Command{
			Token:     h.rawToken,
			IPAddress: "203.0.113.10",
			UserAgent: "Mozilla/5.0",
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Email != h.account.Email {
		t.Errorf("result email = %q, want %q", result.Email, h.account.Email)
	}

	if result.VerifiedAt.IsZero() {
		t.Error("result VerifiedAt is zero")
	}

	if h.users.markVerifiedCalls != 1 {
		t.Errorf("MarkEmailVerified called %d times, want 1", h.users.markVerifiedCalls)
	}

	if len(h.tokens.consumedIDs) != 1 || h.tokens.consumedIDs[0] != h.token.ID {
		t.Errorf("consumed IDs = %v, want [%v]", h.tokens.consumedIDs, h.token.ID)
	}

	if got := len(h.audit.events); got != 1 {
		t.Fatalf("audit events = %d, want 1", got)
	}

	event := h.audit.events[0]

	if event.Type != audit.EventEmailVerified {
		t.Errorf("event type = %q, want %q", event.Type, audit.EventEmailVerified)
	}

	if !event.Success {
		t.Error("a successful verification must be audited as a success")
	}

	if event.UserID == nil || *event.UserID != h.account.ID {
		t.Errorf("event user ID = %v, want %v", event.UserID, h.account.ID)
	}

	if event.IPAddress != "203.0.113.10" {
		t.Errorf("event IP = %q, want %q", event.IPAddress, "203.0.113.10")
	}

	if event.UserAgent != "Mozilla/5.0" {
		t.Errorf("event user agent = %q, want %q", event.UserAgent, "Mozilla/5.0")
	}
}

// PENDING accounts (not currently produced by register, but the domain
// model supports them) must transition to ACTIVE on verification — that
// is exactly what User.VerifyEmail encodes, and this proves the service
// actually calls it rather than writing EmailVerifiedAt directly.
func TestService_Handle_ActivatesAPendingAccount(t *testing.T) {

	h := newHarness()

	h.account.Status = user.StatusPending

	h.users.account = &h.account

	_, err := h.service().Handle(
		context.Background(),
		Command{Token: h.rawToken},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.account.Status != user.StatusActive {
		t.Errorf("status = %q, want %q after verification", h.account.Status, user.StatusActive)
	}
}

// A second click on the same link — or a client retry — must not fail:
// the state the caller wants is already true. It must not be re-audited
// either, since nothing new happened.
func TestService_Handle_AlreadyConsumedIsIdempotent(t *testing.T) {

	h := newHarness()

	verifiedAt := time.Now().UTC()

	h.token.ConsumedAt = &verifiedAt

	h.tokens.tokens[h.token.Hash] = &h.token

	h.account.EmailVerifiedAt = &verifiedAt

	h.users.account = &h.account

	result, err := h.service().Handle(
		context.Background(),
		Command{Token: h.rawToken},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.VerifiedAt.Equal(verifiedAt) {
		t.Errorf("VerifiedAt = %v, want %v", result.VerifiedAt, verifiedAt)
	}

	if h.users.markVerifiedCalls != 0 {
		t.Errorf("MarkEmailVerified called %d times, want 0 — nothing should be written again", h.users.markVerifiedCalls)
	}

	if len(h.audit.events) != 0 {
		t.Errorf("audit events = %d, want 0 — a replay is not a new event", len(h.audit.events))
	}
}

// Two callers racing to confirm the identical token is not a security
// signal (unlike refresh's replay handling) — a double-click or two open
// tabs both want the same outcome. The loser must still succeed, with
// the winner's actually-committed VerifiedAt, not its own.
func TestService_Handle_ConcurrentVerifyRaceStillSucceeds(t *testing.T) {

	h := newHarness()

	h.tokens.consumeReturnsFalse = true

	winnerVerifiedAt := time.Now().Add(-time.Second).UTC()

	h.account.EmailVerifiedAt = &winnerVerifiedAt

	h.users.account = &h.account

	result, err := h.service().Handle(
		context.Background(),
		Command{Token: h.rawToken},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.VerifiedAt.Equal(winnerVerifiedAt) {
		t.Errorf("VerifiedAt = %v, want the winner's %v", result.VerifiedAt, winnerVerifiedAt)
	}

	if h.users.markVerifiedCalls != 0 {
		t.Errorf("MarkEmailVerified called %d times, want 0 — the loser must not write", h.users.markVerifiedCalls)
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
				return Command{Token: "never-issued"}
			},

			wantErr: errs.ErrInvalidVerificationToken,
		},
		{
			name: "rejects an expired, unconsumed token",

			setup: func(h *harness) Command {
				h.token.ExpiresAt = time.Now().Add(-time.Minute)
				h.tokens.tokens[h.token.Hash] = &h.token
				return Command{Token: h.rawToken}
			},

			wantErr: errs.ErrInvalidVerificationToken,
		},
		{
			name: "propagates a token lookup failure",

			setup: func(h *harness) Command {
				h.tokens.findErr = errBackendDown
				return Command{Token: h.rawToken}
			},

			wantErr: errBackendDown,
		},
		{
			name: "propagates a user lookup failure",

			setup: func(h *harness) Command {
				h.users.findErr = errBackendDown
				return Command{Token: h.rawToken}
			},

			wantErr: errBackendDown,
		},
		{
			name: "propagates a transaction failure",

			setup: func(h *harness) Command {
				h.transaction.err = errBackendDown
				return Command{Token: h.rawToken}
			},

			wantErr: errBackendDown,
		},
		{
			name: "propagates a mark-verified failure",

			setup: func(h *harness) Command {
				h.users.markVerifiedErr = errBackendDown
				return Command{Token: h.rawToken}
			},

			wantErr: errBackendDown,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			h := newHarness()

			cmd := tt.setup(h)

			result, err := h.service().Handle(
				context.Background(),
				cmd,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}

			if result != nil {
				t.Errorf("result = %+v, want nil on error", result)
			}
		})
	}
}
