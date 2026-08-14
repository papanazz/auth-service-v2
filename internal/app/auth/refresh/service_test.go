package refresh

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	domainRefresh "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

func TestService_Handle_Success(t *testing.T) {

	h := newHarness()

	result, err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken == "" {
		t.Error("access token is empty")
	}

	if result.RefreshToken == "" {
		t.Fatal("refresh token is empty")
	}

	if result.RefreshToken == h.rawToken {
		t.Fatal("the same refresh token was returned — rotation did not happen")
	}

	if result.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive TTL", result.ExpiresIn)
	}

	// The presented token must now be consumed.
	consumed := h.refreshTokens.byID[h.current.ID]

	if consumed.ConsumedAt == nil {
		t.Error("the presented token was not consumed")
	}

	// The replacement must chain to its parent inside the same family, which is
	// what makes family-wide revocation possible on replay.
	if h.refreshTokens.createdCount() != 1 {
		t.Fatalf("created %d tokens, want 1", h.refreshTokens.createdCount())
	}

	issued := h.refreshTokens.created[0]

	if issued.FamilyID != h.current.FamilyID {
		t.Error("replacement token started a new family")
	}

	if issued.ParentTokenID == nil || *issued.ParentTokenID != h.current.ID {
		t.Error("replacement token does not chain to the consumed token")
	}

	if issued.SessionID != h.current.SessionID {
		t.Error("replacement token is bound to a different session")
	}

	if issued.Hash == result.RefreshToken {
		t.Fatal("raw refresh token was persisted instead of its hash")
	}

	if issued.ExpiresAt.IsZero() || !issued.ExpiresAt.After(time.Now()) {
		t.Errorf("replacement token expires at %v, which is not in the future", issued.ExpiresAt)
	}

	if h.sessions.refreshedCalls != 1 {
		t.Errorf("session last_refreshed_at updated %d times, want 1", h.sessions.refreshedCalls)
	}

	if got := h.audit.countOf(audit.EventTokenRefresh); got != 1 {
		t.Errorf("TOKEN_REFRESH audit events = %d, want 1", got)
	}
}

// The audit trail must carry the same client context login's does, and the
// session actually involved — not just the user.
func TestService_Handle_AuditEventCarriesContext(t *testing.T) {

	h := newHarness()

	_, err := h.service().Handle(
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

// Regression test: refreshFailedEvent's session-lookup-failure branch once
// passed the session ID as the userID argument, silently writing the wrong
// identifier into the audit trail's user_id column. The session ID must
// land in SessionID; UserID must stay nil, since the failed lookup is
// exactly what leaves the user unresolved.
func TestService_Handle_SessionLookupFailureDoesNotMisattributeUserID(t *testing.T) {

	h := newHarness()

	delete(h.sessions.stored, h.session.ID)

	_, err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	)

	if !errors.Is(err, errs.ErrInvalidRefreshToken) {
		t.Fatalf("error = %v, want %v", err, errs.ErrInvalidRefreshToken)
	}

	if len(h.audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(h.audit.events))
	}

	event := h.audit.events[0]

	if event.UserID != nil {
		t.Errorf("event user ID = %v, want nil — the user was never resolved", event.UserID)
	}

	if event.SessionID == nil || *event.SessionID != h.session.ID {
		t.Errorf("event session ID = %v, want %v", event.SessionID, h.session.ID)
	}
}

// Regression test: the access token minted on refresh must carry the real
// session ID. It previously left SessionID unset, so every access token
// issued via refresh carried a zeroed "sid" claim instead of the session's
// actual ID.
func TestService_Handle_AccessTokenCarriesSessionID(t *testing.T) {

	h := newHarness()

	if _, err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(h.accessTokens.claims) != 1 {
		t.Fatalf("access token generated %d times, want 1", len(h.accessTokens.claims))
	}

	got := h.accessTokens.claims[0].SessionID

	if got != h.session.ID {
		t.Errorf("access token SessionID = %v, want %v", got, h.session.ID)
	}
}

// Regression test for the reported outage: refresh returned
// ErrInvalidRefreshToken for every request because the session carried a zero
// ExpiresAt, which always compares as already past.
func TestService_Handle_AcceptsSessionWithValidExpiry(t *testing.T) {

	h := newHarness()

	// Exactly the state login produces once it stamps the session TTL.
	h.mutateSession(func(s *session.Session) {})

	if _, err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	); err != nil {
		t.Fatalf("refresh against a live session failed: %v", err)
	}
}

// A session whose ExpiresAt was never written reaches the service as the zero
// time. That must be rejected as expired rather than silently accepted.
func TestService_Handle_RejectsSessionWithZeroExpiry(t *testing.T) {

	h := newHarness()

	h.mutateSession(func(s *session.Session) {
		s.ExpiresAt = time.Time{}
	})

	_, err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	)

	if !errors.Is(err, errs.ErrInvalidRefreshToken) {
		t.Fatalf("error = %v, want %v", err, errs.ErrInvalidRefreshToken)
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
			name: "rejects an expired token",

			setup: func(h *harness) Command {
				h.mutateToken(func(tok *domainRefresh.Token) {
					tok.ExpiresAt = time.Now().Add(-time.Minute)
				})
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errs.ErrInvalidRefreshToken,
		},
		{
			name: "rejects a revoked token",

			setup: func(h *harness) Command {
				now := time.Now()
				h.mutateToken(func(tok *domainRefresh.Token) {
					tok.RevokedAt = &now
				})
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errs.ErrInvalidRefreshToken,
		},
		{
			name: "rejects a revoked session",

			setup: func(h *harness) Command {
				now := time.Now()
				h.mutateSession(func(s *session.Session) {
					s.RevokedAt = &now
				})
				return Command{RefreshToken: h.rawToken}
			},

			wantErr: errs.ErrInvalidRefreshToken,
		},
		{
			name: "rejects an expired session",

			setup: func(h *harness) Command {
				h.mutateSession(func(s *session.Session) {
					s.ExpiresAt = time.Now().Add(-time.Minute)
				})
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
			name: "propagates an access token failure",

			setup: func(h *harness) Command {
				h.accessTokens.err = errBackendDown
				return Command{RefreshToken: h.rawToken}
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

// Presenting an already-consumed token is the signature of a stolen token being
// replayed. The whole family must be revoked, not just the presented token.
func TestService_Handle_ReplayRevokesFamily(t *testing.T) {

	h := newHarness()

	consumedAt := time.Now().Add(-time.Minute)

	h.mutateToken(func(tok *domainRefresh.Token) {
		tok.ConsumedAt = &consumedAt
	})

	_, err := h.service().Handle(
		context.Background(),
		Command{RefreshToken: h.rawToken},
	)

	if !errors.Is(err, errs.ErrRefreshTokenReplay) {
		t.Fatalf("error = %v, want %v", err, errs.ErrRefreshTokenReplay)
	}

	if h.refreshTokens.revocationCount() != 1 {
		t.Errorf("family revoked %d times, want 1", h.refreshTokens.revocationCount())
	}

	if got := h.audit.countOf(audit.EventTokenReuseDetected); got != 1 {
		t.Errorf(
			"TOKEN_REUSE_DETECTED audit events = %d, want 1 (events seen: %v)",
			got,
			h.audit.typesSeen(),
		)
	}
}

// The centerpiece: N clients racing to redeem the same refresh token.
//
// Consume is a conditional UPDATE guarded by `consumed_at IS NULL`, so exactly
// one caller may win. Every loser must be treated as a replay, and the family
// revoked — a token redeemed twice is indistinguishable from a stolen one.
func TestService_Handle_ConcurrentRefreshAllowsExactlyOneWinner(t *testing.T) {

	const clients = 32

	h := newHarness()

	service := h.service()

	var (
		wg sync.WaitGroup

		mu sync.Mutex

		successes int

		replays int

		others []error
	)

	start := make(chan struct{})

	for i := 0; i < clients; i++ {

		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			_, err := service.Handle(
				context.Background(),
				Command{RefreshToken: h.rawToken},
			)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err == nil:
				successes++

			case errors.Is(err, errs.ErrRefreshTokenReplay):
				replays++

			default:
				others = append(others, err)
			}
		}()
	}

	close(start)

	wg.Wait()

	if successes != 1 {
		t.Fatalf("%d concurrent refreshes succeeded, want exactly 1", successes)
	}

	if replays != clients-1 {
		t.Errorf("replay rejections = %d, want %d", replays, clients-1)
	}

	if len(others) != 0 {
		t.Errorf("unexpected errors: %v", others)
	}

	// Only the winner may mint a replacement token.
	if h.refreshTokens.createdCount() != 1 {
		t.Errorf("issued %d replacement tokens, want 1", h.refreshTokens.createdCount())
	}

	// Every loser is a replay signal, so the family must have been revoked.
	if h.refreshTokens.revocationCount() == 0 {
		t.Error("concurrent replay did not revoke the token family")
	}
}
