package resendverification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

// The response is identical whether the email is unregistered, already
// verified, or genuinely needs a new token — see Service.Handle's own
// comment. These three tests prove the INTERNAL behavior differs
// correctly even though the client-visible outcome (no error) does not.
func TestService_Handle_UnknownEmailIsANoOp(t *testing.T) {

	h := newHarness()

	h.users.account = nil

	err := h.service().Handle(
		context.Background(),
		Command{Email: "nobody@example.com"},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.tokens.createdCount() != 0 {
		t.Errorf("tokens created = %d, want 0", h.tokens.createdCount())
	}

	if len(h.emailPublisher.published) != 0 {
		t.Errorf("emails published = %d, want 0", len(h.emailPublisher.published))
	}

	if len(h.audit.events) != 0 {
		t.Errorf("audit events = %d, want 0", len(h.audit.events))
	}
}

func TestService_Handle_AlreadyVerifiedIsANoOp(t *testing.T) {

	h := newHarness()

	now := time.Now().UTC()

	h.account.EmailVerifiedAt = &now

	h.users.account = &h.account

	err := h.service().Handle(
		context.Background(),
		Command{Email: h.account.Email},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.tokens.createdCount() != 0 {
		t.Errorf("tokens created = %d, want 0", h.tokens.createdCount())
	}

	if len(h.emailPublisher.published) != 0 {
		t.Errorf("emails published = %d, want 0", len(h.emailPublisher.published))
	}
}

func TestService_Handle_MintsAndSendsForAnUnverifiedAccountWithNoActiveToken(t *testing.T) {

	h := newHarness()

	err := h.service().Handle(
		context.Background(),
		Command{
			Email:     h.account.Email,
			IPAddress: "203.0.113.10",
			UserAgent: "Mozilla/5.0",
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.tokens.createdCount() != 1 {
		t.Fatalf("tokens created = %d, want 1", h.tokens.createdCount())
	}

	created := h.tokens.created[0]

	if created.UserID != h.account.ID {
		t.Errorf("token user ID = %v, want %v", created.UserID, h.account.ID)
	}

	if created.Hash != "hashed:new-raw-token" {
		t.Errorf("token hash = %q, want the hasher output", created.Hash)
	}

	cached, found, _ := h.cache.GetRawToken(context.Background(), created.ID)

	if !found || cached != "new-raw-token" {
		t.Errorf("cached raw token = (%q, %v), want (\"new-raw-token\", true)", cached, found)
	}

	if len(h.emailPublisher.published) != 1 {
		t.Fatalf("emails published = %d, want 1", len(h.emailPublisher.published))
	}

	published := h.emailPublisher.published[0]

	if published.To != h.account.Email {
		t.Errorf("published To = %q, want %q", published.To, h.account.Email)
	}

	if published.Token != "new-raw-token" {
		t.Errorf("published Token = %q, want the raw token", published.Token)
	}

	if got := len(h.audit.events); got != 1 {
		t.Fatalf("audit events = %d, want 1", got)
	}

	if h.audit.events[0].Type != audit.EventVerificationEmailSent {
		t.Errorf("event type = %q, want %q", h.audit.events[0].Type, audit.EventVerificationEmailSent)
	}
}

// The centerpiece: a still-valid token whose raw value is cached must be
// re-delivered as-is, not replaced.
func TestService_Handle_ReusesTheActiveTokenWhenItsRawValueIsCached(t *testing.T) {

	h := newHarness()

	existing := verification.Token{
		ID: uuid.New(),

		UserID: h.account.ID,

		Hash: "hashed:existing-raw-token",

		ExpiresAt: time.Now().Add(time.Hour),

		CreatedAt: time.Now(),
	}

	h.tokens.activeByUser[h.account.ID] = &existing

	_ = h.cache.StoreRawToken(context.Background(), existing.ID, "existing-raw-token", time.Hour)

	err := h.service().Handle(
		context.Background(),
		Command{Email: h.account.Email},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.tokens.createdCount() != 0 {
		t.Errorf("tokens created = %d, want 0 — the existing token must be reused", h.tokens.createdCount())
	}

	if len(h.emailPublisher.published) != 1 {
		t.Fatalf("emails published = %d, want 1", len(h.emailPublisher.published))
	}

	if h.emailPublisher.published[0].Token != "existing-raw-token" {
		t.Errorf("published Token = %q, want the reused raw token", h.emailPublisher.published[0].Token)
	}
}

// Self-healing: if the DB record is still valid but its raw value fell
// out of the cache (eviction, Redis restart, ...), a fresh token must be
// minted rather than leaving the caller with nothing to send. The old
// token is left alone — multiple concurrently-valid tokens for one user
// are harmless.
func TestService_Handle_MintsFreshTokenWhenActiveTokensRawValueIsNotCached(t *testing.T) {

	h := newHarness()

	existing := verification.Token{
		ID: uuid.New(),

		UserID: h.account.ID,

		Hash: "hashed:existing-raw-token",

		ExpiresAt: time.Now().Add(time.Hour),

		CreatedAt: time.Now(),
	}

	h.tokens.activeByUser[h.account.ID] = &existing

	// Deliberately not cached.

	err := h.service().Handle(
		context.Background(),
		Command{Email: h.account.Email},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.tokens.createdCount() != 1 {
		t.Fatalf("tokens created = %d, want 1", h.tokens.createdCount())
	}

	if h.tokens.created[0].ID == existing.ID {
		t.Error("a fresh token must be minted, not reuse the existing token's ID")
	}

	if len(h.emailPublisher.published) != 1 || h.emailPublisher.published[0].Token != "new-raw-token" {
		t.Errorf("published emails = %+v, want one carrying the freshly minted token", h.emailPublisher.published)
	}
}

func TestService_Handle_RateLimiting(t *testing.T) {

	t.Run("rejects a request over the IP limit", func(t *testing.T) {

		h := newHarness()

		h.tracker.blocked = true

		err := h.service().Handle(
			context.Background(),
			Command{Email: h.account.Email},
		)

		if !errors.Is(err, errs.ErrTooManyRequests) {
			t.Fatalf("error = %v, want %v", err, errs.ErrTooManyRequests)
		}

		if len(h.emailPublisher.published) != 0 {
			t.Errorf("emails published = %d, want 0", len(h.emailPublisher.published))
		}
	})

	t.Run("propagates a rate limiter failure", func(t *testing.T) {

		h := newHarness()

		h.tracker.checkErr = errors.New("redis unreachable")

		err := h.service().Handle(
			context.Background(),
			Command{Email: h.account.Email},
		)

		if err == nil {
			t.Fatal("expected an error when the rate limiter is unreachable")
		}
	})

	// The counter must advance even on the no-op paths (unknown email,
	// already verified) — those are exactly what an enumeration attempt
	// generates in bulk, same reasoning as register's limiter.
	t.Run("counts an attempt even when it resolves to a no-op", func(t *testing.T) {

		h := newHarness()

		h.users.account = nil

		if err := h.service().Handle(
			context.Background(),
			Command{Email: "nobody@example.com"},
		); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(h.tracker.failures) != 1 {
			t.Errorf("rate limit counter incremented %d times, want 1", len(h.tracker.failures))
		}
	})
}

func TestService_Handle_PropagatesAnUnexpectedLookupFailure(t *testing.T) {

	h := newHarness()

	h.users.findErr = errors.New("connection refused")

	err := h.service().Handle(
		context.Background(),
		Command{Email: h.account.Email},
	)

	if !errors.Is(err, h.users.findErr) {
		t.Fatalf("error = %v, want %v", err, h.users.findErr)
	}
}
