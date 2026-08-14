package login

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
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

func TestLoginService_Handle_RecordsLastLoginAt(t *testing.T) {

	h := newHarness()

	account := h.activeAccount("bayu@example.com")

	if _, err := h.service().Handle(
		context.Background(),
		validCommand(),
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(h.users.updateLastLoginAtCalls) != 1 {
		t.Fatalf("UpdateLastLoginAt called %d times, want 1", len(h.users.updateLastLoginAtCalls))
	}

	if h.users.updateLastLoginAtCalls[0] != account.ID {
		t.Errorf("UpdateLastLoginAt called with %v, want %v", h.users.updateLastLoginAtCalls[0], account.ID)
	}
}

// A failure recording the timestamp is not critical (see queries/user.sql's
// own comment) and must not fail a login that already succeeded.
func TestLoginService_Handle_TolerateLastLoginAtFailure(t *testing.T) {

	h := newHarness()

	h.activeAccount("bayu@example.com")

	h.users.updateLastLoginAtErr = errBackendDown

	result, err := h.service().Handle(
		context.Background(),
		validCommand(),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected a result despite the UpdateLastLoginAt failure")
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

// A device may hold at most one active session. A second login within the
// grace period is assumed to be the same client retrying (e.g. after a
// network timeout that lost the first response), so the stale session is
// superseded rather than left to collide with the new one.
func TestLoginService_Handle_SupersedesRecentSessionOnSameDevice(t *testing.T) {

	h := newHarness()

	account := h.activeAccount("bayu@example.com")

	cmd := validCommand()

	existing := h.activeSessionForDevice(
		account.ID,
		cmd.DeviceID,
		time.Now().Add(-1*time.Minute),
	)

	result, err := h.service().Handle(
		context.Background(),
		cmd,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken == "" {
		t.Error("access token is empty")
	}

	if len(h.sessions.revokedSessions) != 1 || h.sessions.revokedSessions[0] != existing.ID {
		t.Fatalf("revoked sessions = %v, want [%v]", h.sessions.revokedSessions, existing.ID)
	}

	if h.sessions.revokedReasons[0] != session.RevokeSessionSuperseded {
		t.Errorf("revoke reason = %v, want %v", h.sessions.revokedReasons[0], session.RevokeSessionSuperseded)
	}

	if len(h.sessions.created) != 1 {
		t.Fatalf("created %d sessions, want 1", len(h.sessions.created))
	}

	if h.sessions.created[0].ID == existing.ID {
		t.Error("login must mint a new session rather than reuse the superseded one")
	}
}

// Past the grace period, an existing active session on the device is left
// alone and the new login is rejected — silently killing a session that has
// been active for a while looks more like a bug or an attacker than a retry.
func TestLoginService_Handle_RejectsStaleSessionOnSameDevice(t *testing.T) {

	h := newHarness()

	account := h.activeAccount("bayu@example.com")

	cmd := validCommand()

	existing := h.activeSessionForDevice(
		account.ID,
		cmd.DeviceID,
		time.Now().Add(-1*time.Hour),
	)

	result, err := h.service().Handle(
		context.Background(),
		cmd,
	)

	if !errors.Is(err, errs.ErrDeviceSessionActive) {
		t.Fatalf("error = %v, want %v", err, errs.ErrDeviceSessionActive)
	}

	if result != nil {
		t.Errorf("result = %+v, want nil on error", result)
	}

	if len(h.sessions.revokedSessions) != 0 {
		t.Errorf("revoked sessions = %v, want none — the existing session must be left alone", h.sessions.revokedSessions)
	}

	if len(h.sessions.created) != 0 {
		t.Errorf("created %d sessions, want 0", len(h.sessions.created))
	}

	stored := h.sessions.stored[existing.ID]

	if stored.RevokedAt != nil {
		t.Error("the stale session must not be revoked by a rejected login")
	}

	if got := h.audit.types(); len(got) != 1 || got[0] != audit.EventLoginFailed {
		t.Errorf("audit events = %v, want a single LOGIN_FAILED", got)
	}
}

// A different device_id for the same user must not collide — the unique
// constraint (and this check) are scoped per device, not per user.
func TestLoginService_Handle_DifferentDeviceIsUnaffectedByExistingSession(t *testing.T) {

	h := newHarness()

	account := h.activeAccount("bayu@example.com")

	h.activeSessionForDevice(
		account.ID,
		"a-different-device",
		time.Now(),
	)

	cmd := validCommand()

	if _, err := h.service().Handle(
		context.Background(),
		cmd,
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(h.sessions.revokedSessions) != 0 {
		t.Errorf("revoked sessions = %v, want none", h.sessions.revokedSessions)
	}
}

// The centerpiece: N clients racing to log in from the same device at once —
// e.g. a flaky network causing rapid-fire retries. Before the device lock,
// each transaction could read the same pre-existing session as
// supersede-able and then race the others into uq_sessions_active_device,
// surfacing as a raw 500. With the lock in place, transactions serialize on
// the device slot: each one either creates the session or supersedes the
// one immediately before it, and every caller gets a clean success.
func TestLoginService_Handle_ConcurrentLoginsOnSameDeviceAllSucceed(t *testing.T) {

	const clients = 16

	h := newHarness()

	h.activeAccount("bayu@example.com")

	cmd := validCommand()

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

			_, err := service.Handle(
				context.Background(),
				cmd,
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
		t.Fatalf("%d/%d concurrent logins failed: %v", len(failures), clients, failures)
	}

	if len(h.sessions.created) != clients {
		t.Fatalf("created %d sessions, want %d", len(h.sessions.created), clients)
	}

	active := 0

	for _, s := range h.sessions.stored {

		if s.RevokedAt == nil {
			active++
		}
	}

	if active != 1 {
		t.Errorf("active sessions after the race = %d, want exactly 1", active)
	}

	if len(h.sessions.revokedSessions) != clients-1 {
		t.Errorf("revoked sessions = %d, want %d", len(h.sessions.revokedSessions), clients-1)
	}

	if h.sessions.lockDeviceCalls != clients {
		t.Errorf("device lock acquired %d times, want %d (once per transaction attempt)", h.sessions.lockDeviceCalls, clients)
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
			name: "rejects an empty device ID",

			setup: func(h *harness) Command {
				cmd := validCommand()
				cmd.DeviceID = "  "
				return cmd
			},

			wantErr: errs.ErrInvalidRequest,
		},
		{
			name: "rejects an unknown device type",

			setup: func(h *harness) Command {
				cmd := validCommand()
				cmd.DeviceType = "TOASTER"
				return cmd
			},

			wantErr: errs.ErrInvalidRequest,
		},
		{
			name: "rejects a locked account with the correct password",

			setup: func(h *harness) Command {
				h.lockedAccount("bayu@example.com")
				return validCommand()
			},

			wantErr: errs.ErrAccountLocked,
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
		{
			name: "propagates a device session lookup failure",

			setup: func(h *harness) Command {
				h.activeAccount("bayu@example.com")
				h.sessions.findActiveByDeviceErr = errBackendDown
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

// The correct password against a locked account must not count as a
// credential-guessing failure — the caller proved they know the password,
// so charging it against the rate limiter would let anyone who already
// knows a locked account's password lock out its legitimate owner by
// hammering this path. It must still show up in the audit trail.
func TestLoginService_Handle_LockedAccountIsNotRateLimitedButIsAudited(t *testing.T) {

	h := newHarness()

	account := h.lockedAccount("bayu@example.com")

	_, err := h.service().Handle(
		context.Background(),
		validCommand(),
	)

	if !errors.Is(err, errs.ErrAccountLocked) {
		t.Fatalf("error = %v, want %v", err, errs.ErrAccountLocked)
	}

	if len(h.tracker.failures) != 0 {
		t.Errorf("credential failures recorded = %d, want 0 — the password was correct", len(h.tracker.failures))
	}

	if got := h.audit.types(); len(got) != 1 || got[0] != audit.EventLoginFailed {
		t.Fatalf("audit events = %v, want a single LOGIN_FAILED", got)
	}

	event := h.audit.events[0]

	if event.UserID == nil || *event.UserID != account.ID {
		t.Errorf("event user ID = %v, want %v", event.UserID, account.ID)
	}

	if len(h.users.updateLastLoginAtCalls) != 0 {
		t.Errorf("UpdateLastLoginAt called %d times, want 0 — the login did not succeed", len(h.users.updateLastLoginAtCalls))
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
