package oauthcallback

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/app/auth/sessionissuer"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/oauth"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

// errBackendDown stands in for any unexpected infrastructure failure.
var errBackendDown = errors.New("connection refused")

//
// Harness
//

type harness struct {
	exchanger *mockExchanger

	stateStore *mockStateStore

	identities *mockOAuthRepository

	users *mockUserRepository

	transaction *mockTransactionManager

	sessions *mockSessionRepository

	refreshTokens *mockRefreshRepository

	accessTokens *mockAccessTokenService

	refreshGenerator mockRefreshGenerator

	verificationTokens *mockVerificationRepository

	verificationCache *mockVerificationCache

	verificationGenerator mockVerificationGenerator

	emailPublisher *mockEmailPublisher

	audit *mockAuditPublisher

	logger *mockLogger

	sessionIssuerPolicy sessionissuer.Policy

	policy SecurityPolicy
}

// defaultPayload is what oauthstart would have stashed for a login
// begun on device "device-1" — the shape every case handler pulls
// device_id/name/type from.
func defaultPayload() oauth.StatePayload {

	return oauth.StatePayload{

		CodeVerifier: "the-code-verifier",

		DeviceID: "device-1",

		DeviceName: "Pixel 9",

		DeviceType: session.DeviceWeb,
	}
}

// defaultIdentity is what a successful Exchange returns by default —
// both the provider's own verification and the target account, when
// one exists, line up as verified.
func defaultIdentity() oauth.Identity {

	return oauth.Identity{

		Provider: oauth.ProviderGoogle,

		ProviderUserID: "google-sub-1",

		Email: "bayu@example.com",

		EmailVerified: true,

		Name: "Bayu",
	}
}

func defaultCommand() Command {

	return Command{

		Code: "auth-code",

		State: "state-1",

		IPAddress: "203.0.113.10",

		UserAgent: "Mozilla/5.0",
	}
}

func newHarness() *harness {

	return &harness{

		exchanger: &mockExchanger{identity: defaultIdentity()},

		stateStore: &mockStateStore{payload: defaultPayload(), found: true},

		identities: &mockOAuthRepository{},

		users: &mockUserRepository{},

		transaction: &mockTransactionManager{},

		sessions: newMockSessionRepository(),

		refreshTokens: &mockRefreshRepository{},

		accessTokens: &mockAccessTokenService{},

		refreshGenerator: mockRefreshGenerator{},

		verificationTokens: &mockVerificationRepository{},

		verificationCache: &mockVerificationCache{},

		verificationGenerator: mockVerificationGenerator{},

		emailPublisher: &mockEmailPublisher{},

		audit: &mockAuditPublisher{},

		logger: &mockLogger{},

		sessionIssuerPolicy: sessionissuer.Policy{

			RefreshTokenTTL: 30 * 24 * time.Hour,

			SessionTTL: 90 * 24 * time.Hour,

			DeviceGracePeriod: 5 * time.Minute,
		},

		policy: SecurityPolicy{

			EmailVerificationTokenTTL: 24 * time.Hour,
		},
	}
}

func (h *harness) service() *Service {

	issuer :=
		sessionissuer.NewIssuer(
			h.transaction,
			h.sessions,
			h.refreshTokens,
			h.accessTokens,
			h.refreshGenerator,
			mockRefreshHasher{},
			h.sessionIssuerPolicy,
		)

	return NewService(
		h.exchanger,
		h.stateStore,
		h.identities,
		h.users,
		issuer,
		h.transaction,
		h.verificationTokens,
		h.verificationCache,
		h.verificationGenerator,
		mockVerificationHasher{},
		h.emailPublisher,
		h.audit,
		h.logger,
		h.policy,
	)
}

// activeAccount registers a login-capable account already linked to
// the default identity's provider_user_id.
func (h *harness) activeAccount(email string) *user.User {

	account := &user.User{

		ID: uuid.New(),

		Email: email,

		Status: user.StatusActive,
	}

	h.users.findByIDFn = func(ctx context.Context, id uuid.UUID) (*user.User, error) {

		if id == account.ID {
			return account, nil
		}

		return nil, errs.ErrUserNotFound
	}

	h.identities.link = &oauth.Link{

		ID: uuid.New(),

		UserID: account.ID,

		Provider: oauth.ProviderGoogle,

		ProviderUserID: defaultIdentity().ProviderUserID,

		Email: email,
	}

	return account
}

//
// Tests
//

func TestService_Handle_ValidatesInput(t *testing.T) {

	tests := []struct {
		name string

		cmd Command
	}{
		{
			name: "empty code",

			cmd: Command{Code: "", State: "state-1"},
		},
		{
			name: "empty state",

			cmd: Command{Code: "auth-code", State: ""},
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			h := newHarness()

			_, err := h.service().Handle(context.Background(), tt.cmd)

			if !errors.Is(err, errs.ErrInvalidRequest) {
				t.Fatalf("error = %v, want %v", err, errs.ErrInvalidRequest)
			}

			if len(h.stateStore.consumeCalls) != 0 {
				t.Error("state should never be consumed for a request that fails validation")
			}
		})
	}
}

func TestService_Handle_State(t *testing.T) {

	t.Run("rejects an unknown, expired, or already-consumed state", func(t *testing.T) {

		h := newHarness()

		h.stateStore.found = false

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errs.ErrInvalidOAuthState) {
			t.Fatalf("error = %v, want %v", err, errs.ErrInvalidOAuthState)
		}
	})

	t.Run("propagates a state store failure", func(t *testing.T) {

		h := newHarness()

		h.stateStore.consumeErr = errBackendDown

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errBackendDown) {
			t.Fatalf("error = %v, want %v", err, errBackendDown)
		}
	})
}

func TestService_Handle_Exchange(t *testing.T) {

	h := newHarness()

	h.exchanger.err = errBackendDown

	_, err := h.service().Handle(context.Background(), defaultCommand())

	if !errors.Is(err, errBackendDown) {
		t.Fatalf("error = %v, want %v", err, errBackendDown)
	}
}

func TestService_Handle_ExchangeUsesTheStatePayloadVerifier(t *testing.T) {

	h := newHarness()

	_, err := h.service().Handle(context.Background(), defaultCommand())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.exchanger.seenCode != "auth-code" {
		t.Errorf("exchange code = %q, want %q", h.exchanger.seenCode, "auth-code")
	}

	if h.exchanger.seenVerifier != "the-code-verifier" {
		t.Errorf("exchange verifier = %q, want the one carried by the state payload", h.exchanger.seenVerifier)
	}
}

//
// Case 1: identity already linked to an account.
//

func TestService_Handle_LinkedIdentity(t *testing.T) {

	t.Run("logs in the linked account", func(t *testing.T) {

		h := newHarness()

		account := h.activeAccount("bayu@example.com")

		result, err := h.service().Handle(context.Background(), defaultCommand())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.AccessToken == "" || result.RefreshToken == "" {
			t.Fatalf("result = %+v, want non-empty tokens", result)
		}

		if len(h.sessions.created) != 1 {
			t.Fatalf("sessions created = %d, want 1", len(h.sessions.created))
		}

		created := h.sessions.created[0]

		if created.UserID != account.ID {
			t.Errorf("session user ID = %v, want %v", created.UserID, account.ID)
		}

		if created.DeviceID != "device-1" || created.DeviceName != "Pixel 9" || created.DeviceType != session.DeviceWeb {
			t.Errorf("session device fields = %+v, want the ones carried by the state payload", created)
		}

		if len(h.users.updateLastLoginAtCalls) != 1 || h.users.updateLastLoginAtCalls[0] != account.ID {
			t.Errorf("UpdateLastLoginAt calls = %v, want [%v]", h.users.updateLastLoginAtCalls, account.ID)
		}

		if types := h.audit.types(); len(types) != 1 || types[0] != audit.EventLoginSuccess {
			t.Errorf("audit events = %v, want [%v]", types, audit.EventLoginSuccess)
		}
	})

	t.Run("propagates a lookup failure for the linked account", func(t *testing.T) {

		h := newHarness()

		h.identities.link = &oauth.Link{UserID: uuid.New(), Provider: oauth.ProviderGoogle, ProviderUserID: defaultIdentity().ProviderUserID}

		h.users.findByIDFn = func(ctx context.Context, id uuid.UUID) (*user.User, error) {
			return nil, errBackendDown
		}

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errBackendDown) {
			t.Fatalf("error = %v, want %v", err, errBackendDown)
		}
	})

	t.Run("propagates an unexpected link lookup failure", func(t *testing.T) {

		h := newHarness()

		h.identities.findErr = errBackendDown

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errBackendDown) {
			t.Fatalf("error = %v, want %v", err, errBackendDown)
		}
	})

	t.Run("rejects a locked account without revealing why beforehand", func(t *testing.T) {

		h := newHarness()

		account := h.activeAccount("bayu@example.com")

		lockedUntil := time.Now().Add(time.Hour)

		account.Status = user.StatusLocked

		account.LockedUntil = &lockedUntil

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errs.ErrAccountLocked) {
			t.Fatalf("error = %v, want %v", err, errs.ErrAccountLocked)
		}

		if len(h.sessions.created) != 0 {
			t.Error("a locked account must not get a session")
		}

		if types := h.audit.types(); len(types) != 1 || types[0] != audit.EventLoginFailed {
			t.Errorf("audit events = %v, want [%v]", types, audit.EventLoginFailed)
		}
	})

	t.Run("propagates and audits an active session on the same device", func(t *testing.T) {

		h := newHarness()

		account := h.activeAccount("bayu@example.com")

		existing := &session.Session{

			ID: uuid.New(),

			UserID: account.ID,

			DeviceID: "device-1",

			CreatedAt: time.Now().Add(-time.Hour),

			ExpiresAt: time.Now().Add(time.Hour),
		}

		h.sessions.stored[existing.ID] = existing

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errs.ErrDeviceSessionActive) {
			t.Fatalf("error = %v, want %v", err, errs.ErrDeviceSessionActive)
		}

		if types := h.audit.types(); len(types) != 1 || types[0] != audit.EventLoginFailed {
			t.Errorf("audit events = %v, want [%v]", types, audit.EventLoginFailed)
		}
	})
}

//
// Case 2: no link, no existing account for this email — auto-register.
//

func TestService_Handle_AutoRegister(t *testing.T) {

	t.Run("provider-verified email skips the verification flow", func(t *testing.T) {

		h := newHarness()

		result, err := h.service().Handle(context.Background(), defaultCommand())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.AccessToken == "" {
			t.Fatal("expected tokens to be issued")
		}

		if h.users.created == nil {
			t.Fatal("account was never created")
		}

		if h.users.created.Email != "bayu@example.com" {
			t.Errorf("created email = %q, want %q", h.users.created.Email, "bayu@example.com")
		}

		if h.users.created.Status != user.StatusActive {
			t.Errorf("created status = %q, want %q", h.users.created.Status, user.StatusActive)
		}

		if h.users.created.EmailVerifiedAt == nil {
			t.Error("a provider-verified email must be recorded as verified immediately")
		}

		if h.users.created.PasswordHash != nil {
			t.Error("an OAuth-only account must not have a password hash")
		}

		if len(h.identities.created) != 1 {
			t.Fatalf("oauth links created = %d, want 1", len(h.identities.created))
		}

		if h.identities.created[0].UserID != h.users.created.ID {
			t.Errorf("link user ID = %v, want %v", h.identities.created[0].UserID, h.users.created.ID)
		}

		if len(h.verificationTokens.created) != 0 {
			t.Error("no verification token should be issued when the provider already asserts the email verified")
		}

		if types := h.audit.types(); len(types) != 2 || types[0] != audit.EventUserRegistered || types[1] != audit.EventLoginSuccess {
			t.Errorf("audit events = %v, want [%v %v]", types, audit.EventUserRegistered, audit.EventLoginSuccess)
		}
	})

	t.Run("unverified provider email falls back to the verification flow", func(t *testing.T) {

		h := newHarness()

		identity := defaultIdentity()

		identity.EmailVerified = false

		h.exchanger.identity = identity

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.users.created.EmailVerifiedAt != nil {
			t.Error("an unverified provider email must not be recorded as verified")
		}

		if len(h.verificationTokens.created) != 1 {
			t.Fatalf("verification tokens created = %d, want 1", len(h.verificationTokens.created))
		}

		token := h.verificationTokens.created[0]

		if token.UserID != h.users.created.ID {
			t.Errorf("token user ID = %v, want %v", token.UserID, h.users.created.ID)
		}

		cached, found, _ := h.verificationCache.GetRawToken(context.Background(), token.ID)

		if !found {
			t.Fatal("raw token was not cached")
		}

		if cached != "raw-verification-token" {
			t.Errorf("cached raw token = %q, want %q", cached, "raw-verification-token")
		}

		if len(h.emailPublisher.published) != 1 {
			t.Fatalf("verification emails published = %d, want 1", len(h.emailPublisher.published))
		}

		if h.emailPublisher.published[0].To != "bayu@example.com" {
			t.Errorf("published To = %q, want %q", h.emailPublisher.published[0].To, "bayu@example.com")
		}
	})

	t.Run("propagates a transaction failure and audits nothing", func(t *testing.T) {

		h := newHarness()

		h.transaction.err = errBackendDown

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errBackendDown) {
			t.Fatalf("error = %v, want %v", err, errBackendDown)
		}

		if len(h.audit.events) != 0 {
			t.Errorf("audit events = %d, want 0 on a failed registration", len(h.audit.events))
		}
	})

	t.Run("propagates an unexpected email lookup failure", func(t *testing.T) {

		h := newHarness()

		h.users.findByEmailFn = func(ctx context.Context, email string) (*user.User, error) {
			return nil, errBackendDown
		}

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errBackendDown) {
			t.Fatalf("error = %v, want %v", err, errBackendDown)
		}
	})
}

//
// Case 3: no link, but an account already owns this email.
//

func TestService_Handle_EmailCollision(t *testing.T) {

	existingAccount := func() *user.User {

		verifiedAt := time.Now().Add(-24 * time.Hour)

		return &user.User{

			ID: uuid.New(),

			Email: "bayu@example.com",

			Status: user.StatusActive,

			EmailVerifiedAt: &verifiedAt,
		}
	}

	t.Run("auto-links and logs in when both sides are verified", func(t *testing.T) {

		h := newHarness()

		account := existingAccount()

		h.users.findByEmailFn = func(ctx context.Context, email string) (*user.User, error) {
			return account, nil
		}

		result, err := h.service().Handle(context.Background(), defaultCommand())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.AccessToken == "" {
			t.Fatal("expected tokens to be issued")
		}

		if len(h.identities.created) != 1 {
			t.Fatalf("oauth links created = %d, want 1", len(h.identities.created))
		}

		if h.identities.created[0].UserID != account.ID {
			t.Errorf("link user ID = %v, want %v", h.identities.created[0].UserID, account.ID)
		}

		if types := h.audit.types(); len(types) != 2 || types[0] != audit.EventOAuthAccountLinked || types[1] != audit.EventLoginSuccess {
			t.Errorf("audit events = %v, want [%v %v]", types, audit.EventOAuthAccountLinked, audit.EventLoginSuccess)
		}
	})

	t.Run("rejects when the provider's own assertion is unverified", func(t *testing.T) {

		h := newHarness()

		account := existingAccount()

		h.users.findByEmailFn = func(ctx context.Context, email string) (*user.User, error) {
			return account, nil
		}

		identity := defaultIdentity()

		identity.EmailVerified = false

		h.exchanger.identity = identity

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errs.ErrUserAlreadyExists) {
			t.Fatalf("error = %v, want %v", err, errs.ErrUserAlreadyExists)
		}

		if len(h.identities.created) != 0 {
			t.Error("must not auto-link when the provider does not assert the email verified")
		}
	})

	t.Run("rejects when the existing account's own email is unverified", func(t *testing.T) {

		h := newHarness()

		account := existingAccount()

		account.EmailVerifiedAt = nil

		h.users.findByEmailFn = func(ctx context.Context, email string) (*user.User, error) {
			return account, nil
		}

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errs.ErrUserAlreadyExists) {
			t.Fatalf("error = %v, want %v", err, errs.ErrUserAlreadyExists)
		}

		if len(h.identities.created) != 0 {
			t.Error("must not auto-link when the target account's own email is unverified")
		}
	})

	// Linking happens before the account-status gate: the identity is a
	// durable fact about the account regardless of whether this
	// particular sign-in attempt is allowed to proceed, mirroring case
	// 1's "the link is real even if this login isn't."
	t.Run("still links a locked account, but refuses to log it in", func(t *testing.T) {

		h := newHarness()

		account := existingAccount()

		lockedUntil := time.Now().Add(time.Hour)

		account.Status = user.StatusLocked

		account.LockedUntil = &lockedUntil

		h.users.findByEmailFn = func(ctx context.Context, email string) (*user.User, error) {
			return account, nil
		}

		_, err := h.service().Handle(context.Background(), defaultCommand())

		if !errors.Is(err, errs.ErrAccountLocked) {
			t.Fatalf("error = %v, want %v", err, errs.ErrAccountLocked)
		}

		if len(h.identities.created) != 1 {
			t.Errorf("oauth links created = %d, want 1", len(h.identities.created))
		}

		if len(h.sessions.created) != 0 {
			t.Error("a locked account must not get a session")
		}
	})
}
