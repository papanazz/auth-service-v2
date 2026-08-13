package login

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/platform/authattempt"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func validCommand() Command {

	return Command{
		Email:      "bayu@example.com",
		Password:   "correct-password",
		DeviceID:   "device-1",
		DeviceName: "MacBook Pro",
		DeviceType: "WEB",
		IPAddress:  "203.0.113.10",
		UserAgent:  "Mozilla/5.0",
	}
}

func TestLoginService_Handle_Success(t *testing.T) {

	h := newHarness()

	account := h.activeAccount("bayu@example.com")

	result, err := h.service().Handle(
		context.Background(),
		validCommand(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken == "" {
		t.Error("access token is empty")
	}

	if result.RefreshToken != "raw-refresh-token" {
		t.Errorf("refresh token = %q, want the generator output", result.RefreshToken)
	}

	if result.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive TTL", result.ExpiresIn)
	}

	// The raw refresh token must never be persisted — only its hash.
	if len(h.refreshTokens.created) != 1 {
		t.Fatalf("created %d refresh tokens, want 1", len(h.refreshTokens.created))
	}

	stored := h.refreshTokens.created[0]

	if stored.Hash == result.RefreshToken {
		t.Fatal("raw refresh token was persisted instead of its hash")
	}

	if stored.Hash != "hashed:"+result.RefreshToken {
		t.Errorf("stored hash = %q, want the hasher output", stored.Hash)
	}

	if stored.ParentTokenID != nil {
		t.Error("the first token in a family must have no parent")
	}

	// The access token must be bound to the session so that revoking the
	// session invalidates the token.
	if len(h.accessTokens.claims) != 1 {
		t.Fatalf("generated %d access tokens, want 1", len(h.accessTokens.claims))
	}

	claims := h.accessTokens.claims[0]

	if claims.UserID != account.ID {
		t.Errorf("claims user = %v, want %v", claims.UserID, account.ID)
	}

	if len(h.sessions.created) != 1 {
		t.Fatalf("created %d sessions, want 1", len(h.sessions.created))
	}

	if claims.SessionID != h.sessions.created[0].ID {
		t.Error("access token claims are not bound to the created session")
	}

	if stored.SessionID != h.sessions.created[0].ID {
		t.Error("refresh token is not bound to the created session")
	}
}

// Regression test for the refresh bug: a session created by login carried a
// zero ExpiresAt, which made every later refresh look expired.
func TestLoginService_Handle_SessionCarriesExpiry(t *testing.T) {

	h := newHarness()

	h.activeAccount("bayu@example.com")

	before := time.Now()

	_, err := h.service().Handle(
		context.Background(),
		validCommand(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	created := h.sessions.created[0]

	if created.ExpiresAt.IsZero() {
		t.Fatal("session ExpiresAt is zero — every refresh against it will be rejected as expired")
	}

	if !created.ExpiresAt.After(before) {
		t.Errorf("session expires at %v, which is not in the future", created.ExpiresAt)
	}

	// It must also outlive the refresh token, otherwise a valid refresh token
	// can be presented against an already-expired session.
	wantAtLeast := before.Add(h.policy.RefreshTokenTTL)

	if created.ExpiresAt.Before(wantAtLeast) {
		t.Errorf(
			"session expires at %v, before the refresh token TTL boundary %v",
			created.ExpiresAt,
			wantAtLeast,
		)
	}
}

// The IP address is collected for security investigation, so it has to survive
// into the persisted session.
func TestLoginService_Handle_SessionRecordsClientContext(t *testing.T) {

	h := newHarness()

	h.activeAccount("bayu@example.com")

	cmd := validCommand()

	_, err := h.service().Handle(context.Background(), cmd)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	created := h.sessions.created[0]

	if created.IPAddress != cmd.IPAddress {
		t.Errorf("session IP = %q, want %q", created.IPAddress, cmd.IPAddress)
	}

	if created.UserAgent != cmd.UserAgent {
		t.Errorf("session user agent = %q, want %q", created.UserAgent, cmd.UserAgent)
	}

	if created.DeviceID != cmd.DeviceID {
		t.Errorf("session device = %q, want %q", created.DeviceID, cmd.DeviceID)
	}
}

func TestLoginService_Handle_Failures(t *testing.T) {

	tests := []struct {
		name string

		setup func(h *harness) Command

		wantErr error
	}{
		{
			name: "rejects a malformed email",

			setup: func(h *harness) Command {
				cmd := validCommand()
				cmd.Email = "not-an-email"
				return cmd
			},

			wantErr: errs.ErrInvalidEmail,
		},
		{
			name: "rejects an empty password",

			setup: func(h *harness) Command {
				cmd := validCommand()
				cmd.Password = ""
				return cmd
			},

			wantErr: errs.ErrInvalidRequest,
		},
		{
			name: "rejects an unknown account without revealing it",

			setup: func(h *harness) Command {
				// no account registered
				return validCommand()
			},

			wantErr: errs.ErrInvalidCredentials,
		},
		{
			name: "rejects a wrong password",

			setup: func(h *harness) Command {
				h.activeAccount("bayu@example.com")
				h.passwords.err = errors.New("mismatch")
				return validCommand()
			},

			wantErr: errs.ErrInvalidCredentials,
		},
		{
			name: "blocks a rate limited IP",

			setup: func(h *harness) Command {
				h.activeAccount("bayu@example.com")
				cmd := validCommand()
				h.tracker.blocked[authattempt.LoginIP(cmd.IPAddress)] = true
				return cmd
			},

			wantErr: errs.ErrTooManyRequests,
		},
		{
			name: "blocks a rate limited credential",

			setup: func(h *harness) Command {
				h.activeAccount("bayu@example.com")
				cmd := validCommand()
				h.tracker.blocked[authattempt.LoginCredential(cmd.Email, cmd.IPAddress)] = true
				return cmd
			},

			wantErr: errs.ErrTooManyRequests,
		},
		{
			name: "propagates a transaction failure",

			setup: func(h *harness) Command {
				h.activeAccount("bayu@example.com")
				h.transaction.err = errBackendDown
				return validCommand()
			},

			wantErr: errBackendDown,
		},
		{
			name: "propagates an access token failure",

			setup: func(h *harness) Command {
				h.activeAccount("bayu@example.com")
				h.accessTokens.err = errBackendDown
				return validCommand()
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

// An attacker must not be able to tell a registered email from an unregistered
// one by timing the response, so the unknown-account path still runs a hash
// verification against a dummy hash.
func TestLoginService_Handle_UnknownAccountRunsDummyVerification(t *testing.T) {

	h := newHarness()

	_, err := h.service().Handle(
		context.Background(),
		validCommand(),
	)

	if !errors.Is(err, errs.ErrInvalidCredentials) {
		t.Fatalf("error = %v, want %v", err, errs.ErrInvalidCredentials)
	}

	if len(h.passwords.seen) != 1 {
		t.Fatalf("verifier called %d times, want 1", len(h.passwords.seen))
	}

	if h.passwords.seen[0] != dummyPasswordHash {
		t.Errorf("verified against %q, want the dummy hash", h.passwords.seen[0])
	}
}

func TestLoginService_Handle_RecordsAuditTrail(t *testing.T) {

	t.Run("success is audited", func(t *testing.T) {

		h := newHarness()

		h.activeAccount("bayu@example.com")

		if _, err := h.service().Handle(
			context.Background(),
			validCommand(),
		); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := []audit.EventType{audit.EventLoginSuccess}

		if got := h.audit.types(); len(got) != 1 || got[0] != want[0] {
			t.Errorf("audit events = %v, want %v", got, want)
		}
	})

	t.Run("failure is audited and counted against the limiter", func(t *testing.T) {

		h := newHarness()

		h.activeAccount("bayu@example.com")

		h.passwords.err = errors.New("mismatch")

		cmd := validCommand()

		if _, err := h.service().Handle(
			context.Background(),
			cmd,
		); !errors.Is(err, errs.ErrInvalidCredentials) {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := h.audit.types(); len(got) != 1 || got[0] != audit.EventLoginFailed {
			t.Errorf("audit events = %v, want a single LOGIN_FAILED", got)
		}

		if len(h.tracker.failures) == 0 {
			t.Error("a failed login was not recorded against the rate limiter")
		}
	})

	t.Run("success resets the credential limiter", func(t *testing.T) {

		h := newHarness()

		h.activeAccount("bayu@example.com")

		cmd := validCommand()

		if _, err := h.service().Handle(
			context.Background(),
			cmd,
		); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		wantKey := authattempt.LoginCredential(cmd.Email, cmd.IPAddress)

		if len(h.tracker.resets) != 1 || h.tracker.resets[0] != wantKey {
			t.Errorf("limiter resets = %v, want [%s]", h.tracker.resets, wantKey)
		}
	})
}
