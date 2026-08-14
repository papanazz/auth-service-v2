package register

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	domainEmail "github.com/papanazz/auth-service-v2/internal/domain/email"
	"github.com/papanazz/auth-service-v2/internal/domain/security"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

//
// Mocks
//

type mockTransactionManager struct {
	err error

	calls int
}

func (m *mockTransactionManager) WithinTransaction(
	ctx context.Context,
	fn func(tx pgx.Tx) error,
) error {

	m.calls++

	if m.err != nil {
		return m.err
	}

	return fn(nil)
}

type mockUserRepository struct {
	findByEmail func(ctx context.Context, email string) (*user.User, error)

	created *user.User

	createErr error
}

func (m *mockUserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*user.User, error) {

	if m.findByEmail != nil {
		return m.findByEmail(ctx, email)
	}

	return nil, errs.ErrUserNotFound
}

func (m *mockUserRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (*user.User, error) {

	return nil, errs.ErrUserNotFound
}

func (m *mockUserRepository) Create(
	ctx context.Context,
	account user.User,
) error {

	if m.createErr != nil {
		return m.createErr
	}

	m.created = &account

	return nil
}

func (m *mockUserRepository) MarkEmailVerified(
	ctx context.Context,
	userID uuid.UUID,
	verifiedAt time.Time,
	status user.Status,
) error {

	return nil
}

func (m *mockUserRepository) WithTx(
	tx pgx.Tx,
) user.Repository {

	return m
}

type mockVerificationRepository struct {
	created []verification.Token

	createErr error
}

func (m *mockVerificationRepository) Create(
	ctx context.Context,
	token verification.Token,
) error {

	if m.createErr != nil {
		return m.createErr
	}

	m.created = append(m.created, token)

	return nil
}

func (m *mockVerificationRepository) FindByHash(
	ctx context.Context,
	hash string,
) (*verification.Token, error) {

	return nil, errs.ErrVerificationTokenNotFound
}

func (m *mockVerificationRepository) FindActiveByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*verification.Token, error) {

	return nil, errs.ErrVerificationTokenNotFound
}

func (m *mockVerificationRepository) Consume(
	ctx context.Context,
	id uuid.UUID,
) (bool, error) {

	return true, nil
}

func (m *mockVerificationRepository) WithTx(
	tx pgx.Tx,
) verification.Repository {

	return m
}

type mockVerificationCache struct {
	mu sync.Mutex

	stored map[uuid.UUID]string

	storeErr error
}

func (m *mockVerificationCache) StoreRawToken(
	ctx context.Context,
	tokenID uuid.UUID,
	rawToken string,
	ttl time.Duration,
) error {

	if m.storeErr != nil {
		return m.storeErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stored == nil {
		m.stored = map[uuid.UUID]string{}
	}

	m.stored[tokenID] = rawToken

	return nil
}

func (m *mockVerificationCache) GetRawToken(
	ctx context.Context,
	tokenID uuid.UUID,
) (string, bool, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	value, ok := m.stored[tokenID]

	return value, ok, nil
}

type mockVerificationGenerator struct {
	value string

	err error
}

func (m mockVerificationGenerator) Generate() (string, error) {

	if m.err != nil {
		return "", m.err
	}

	if m.value == "" {
		return "raw-verification-token", nil
	}

	return m.value, nil
}

type mockVerificationHasher struct{}

func (mockVerificationHasher) Hash(value string) string {
	return "hashed:" + value
}

type mockEmailPublisher struct {
	mu sync.Mutex

	published []domainEmail.VerificationEmail

	err error
}

func (m *mockEmailPublisher) PublishVerificationEmail(
	ctx context.Context,
	verificationEmail domainEmail.VerificationEmail,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return m.err
	}

	m.published = append(m.published, verificationEmail)

	return nil
}

type mockHasher struct {
	err error
}

func (m mockHasher) Hash(password string) (string, error) {

	if m.err != nil {
		return "", m.err
	}

	return "hashed:" + password, nil
}

type mockPolicy struct {
	err error
}

func (m mockPolicy) Validate(password string) error {
	return m.err
}

type mockAuditPublisher struct {
	events []audit.Event
}

func (m *mockAuditPublisher) Publish(ctx context.Context, event audit.Event) error {
	m.events = append(m.events, event)
	return nil
}

type mockAttemptTracker struct {
	mu sync.Mutex

	blocked bool

	checkErr error

	failures []string
}

func (m *mockAttemptTracker) Check(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) (bool, error) {

	if m.checkErr != nil {
		return false, m.checkErr
	}

	return !m.blocked, nil
}

func (m *mockAttemptTracker) RecordFailure(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.failures = append(m.failures, key)

	return nil
}

func (m *mockAttemptTracker) Reset(
	ctx context.Context,
	key string,
) error {

	return nil
}

//
// Harness
//

// harness bundles a full set of working mocks so tests only need to
// override the one dependency their scenario cares about.
type harness struct {
	transaction *mockTransactionManager

	users *mockUserRepository

	verificationTokens *mockVerificationRepository

	verificationCache *mockVerificationCache

	verificationGenerator mockVerificationGenerator

	emailPublisher *mockEmailPublisher

	hasher mockHasher

	policy mockPolicy

	audit *mockAuditPublisher

	tracker *mockAttemptTracker

	securityPolicy SecurityPolicy
}

func newHarness() *harness {

	return &harness{
		transaction: &mockTransactionManager{},

		users: &mockUserRepository{},

		verificationTokens: &mockVerificationRepository{},

		verificationCache: &mockVerificationCache{},

		verificationGenerator: mockVerificationGenerator{},

		emailPublisher: &mockEmailPublisher{},

		audit: &mockAuditPublisher{},

		tracker: &mockAttemptTracker{},

		securityPolicy: testSecurityPolicy(),
	}
}

func (h *harness) service() *RegisterService {

	return NewService(
		h.transaction,
		h.users,
		h.verificationTokens,
		h.verificationCache,
		h.verificationGenerator,
		mockVerificationHasher{},
		h.emailPublisher,
		h.hasher,
		h.policy,
		h.audit,
		h.tracker,
		h.securityPolicy,
	)
}

//
// Tests
//

func testSecurityPolicy() SecurityPolicy {

	return SecurityPolicy{

		IP: security.LimitPolicy{

			Type: security.PolicyRegisterAttempt,

			Limit: 10,

			Window: time.Minute,
		},

		EmailVerificationTokenTTL: 24 * time.Hour,
	}
}

func TestRegisterService_Handle(t *testing.T) {

	errRepositoryDown := errors.New("connection refused")

	tests := []struct {
		name string

		cmd Command

		setup func(h *harness)

		wantErr error

		// checked only when wantErr is nil
		wantEmail string
	}{
		{
			name: "registers a new account",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			wantEmail: "bayu@example.com",
		},
		{
			name: "normalizes email casing and surrounding space",

			cmd: Command{
				Email:    "  BaYu@Example.COM  ",
				Password: "Str0ng!Passphrase",
			},

			wantEmail: "bayu@example.com",
		},
		{
			name: "rejects a malformed email",

			cmd: Command{
				Email:    "not-an-email",
				Password: "Str0ng!Passphrase",
			},

			wantErr: errs.ErrInvalidEmail,
		},
		{
			name: "rejects a password the policy refuses",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "short",
			},

			setup: func(h *harness) {
				h.policy = mockPolicy{err: errs.ErrWeakPassword}
			},

			wantErr: errs.ErrWeakPassword,
		},
		{
			name: "rejects an email that already exists",

			cmd: Command{
				Email:    "taken@example.com",
				Password: "Str0ng!Passphrase",
			},

			setup: func(h *harness) {
				h.users.findByEmail = func(ctx context.Context, email string) (*user.User, error) {
					return &user.User{ID: uuid.New(), Email: email}, nil
				}
			},

			wantErr: errs.ErrUserAlreadyExists,
		},
		{
			name: "propagates an unexpected lookup failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			setup: func(h *harness) {
				h.users.findByEmail = func(ctx context.Context, email string) (*user.User, error) {
					return nil, errRepositoryDown
				}
			},

			wantErr: errRepositoryDown,
		},
		{
			name: "propagates a hashing failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			setup: func(h *harness) {
				h.hasher = mockHasher{err: errRepositoryDown}
			},

			wantErr: errRepositoryDown,
		},
		{
			name: "propagates a user create failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			setup: func(h *harness) {
				h.users.createErr = errRepositoryDown
			},

			wantErr: errRepositoryDown,
		},
		{
			name: "propagates a verification token generation failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			setup: func(h *harness) {
				h.verificationGenerator = mockVerificationGenerator{err: errRepositoryDown}
			},

			wantErr: errRepositoryDown,
		},
		{
			name: "propagates a verification token create failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			setup: func(h *harness) {
				h.verificationTokens.createErr = errRepositoryDown
			},

			wantErr: errRepositoryDown,
		},
		{
			name: "propagates a transaction failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			setup: func(h *harness) {
				h.transaction.err = errRepositoryDown
			},

			wantErr: errRepositoryDown,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			h := newHarness()

			if tt.setup != nil {
				tt.setup(h)
			}

			result, err := h.service().Handle(
				context.Background(),
				tt.cmd,
			)

			if tt.wantErr != nil {

				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}

				if result != nil {
					t.Errorf("result = %+v, want nil on error", result)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Email != tt.wantEmail {
				t.Errorf("result email = %q, want %q", result.Email, tt.wantEmail)
			}

			if _, parseErr := uuid.Parse(result.ID); parseErr != nil {
				t.Errorf("result ID %q is not a valid UUID: %v", result.ID, parseErr)
			}
		})
	}
}

// The password must never be stored in clear text, and the account must be
// persisted with the normalized email so a later login lookup can find it.
func TestRegisterService_PersistsNormalizedAccount(t *testing.T) {

	h := newHarness()

	const plaintext = "Str0ng!Passphrase"

	result, err := h.service().Handle(
		context.Background(),
		Command{
			Email:    "  BaYu@Example.COM ",
			Password: plaintext,
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h.users.created == nil {
		t.Fatal("account was never passed to the repository")
	}

	stored := *h.users.created

	if stored.Email != "bayu@example.com" {
		t.Errorf("stored email = %q, want normalized", stored.Email)
	}

	if stored.PasswordHash == plaintext {
		t.Fatal("password was stored in clear text")
	}

	if stored.PasswordHash != "hashed:"+plaintext {
		t.Errorf("stored hash = %q, want the hasher output", stored.PasswordHash)
	}

	if stored.Status != user.StatusActive {
		t.Errorf("stored status = %q, want %q", stored.Status, user.StatusActive)
	}

	if stored.EmailVerifiedAt != nil {
		t.Error("a newly registered account must not be pre-verified")
	}

	if stored.ID.String() != result.ID {
		t.Errorf("returned ID %q does not match stored ID %q", result.ID, stored.ID)
	}
}

// The centerpiece of the verification flow's registration half: a token
// is created, its raw value cached (so a same-window resend can reuse
// it), and the "email" published — all bound to the account that was
// just created, not some earlier or unrelated one.
func TestRegisterService_Handle_IssuesVerificationToken(t *testing.T) {

	h := newHarness()

	result, err := h.service().Handle(
		context.Background(),
		Command{
			Email:    "bayu@example.com",
			Password: "Str0ng!Passphrase",
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(h.verificationTokens.created) != 1 {
		t.Fatalf("verification tokens created = %d, want 1", len(h.verificationTokens.created))
	}

	token := h.verificationTokens.created[0]

	if token.UserID.String() != result.ID {
		t.Errorf("token user ID = %v, want %v", token.UserID, result.ID)
	}

	if token.Hash != "hashed:raw-verification-token" {
		t.Errorf("token hash = %q, want the hasher output", token.Hash)
	}

	if !token.ExpiresAt.After(time.Now()) {
		t.Errorf("token expires at %v, which is not in the future", token.ExpiresAt)
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

	published := h.emailPublisher.published[0]

	if published.To != "bayu@example.com" {
		t.Errorf("published email To = %q, want %q", published.To, "bayu@example.com")
	}

	if published.Token != "raw-verification-token" {
		t.Errorf("published email Token = %q, want the raw token, not its hash", published.Token)
	}

	if !published.ExpiresAt.Equal(token.ExpiresAt) {
		t.Errorf("published email ExpiresAt = %v, want %v", published.ExpiresAt, token.ExpiresAt)
	}
}

// Neither is on the critical path: an outage in the cache or the email
// publisher must not fail a registration whose account and token were
// already durably persisted.
func TestRegisterService_Handle_ToleratesCacheAndEmailFailures(t *testing.T) {

	t.Run("cache failure", func(t *testing.T) {

		h := newHarness()

		h.verificationCache.storeErr = errors.New("redis unreachable")

		_, err := h.service().Handle(
			context.Background(),
			Command{Email: "bayu@example.com", Password: "Str0ng!Passphrase"},
		)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("email publish failure", func(t *testing.T) {

		h := newHarness()

		h.emailPublisher.err = errors.New("smtp unreachable")

		_, err := h.service().Handle(
			context.Background(),
			Command{Email: "bayu@example.com", Password: "Str0ng!Passphrase"},
		)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestRegisterService_Handle_RecordsAuditTrail(t *testing.T) {

	h := newHarness()

	result, err := h.service().Handle(
		context.Background(),
		Command{
			Email:     "bayu@example.com",
			Password:  "Str0ng!Passphrase",
			IPAddress: "203.0.113.10",
			UserAgent: "Mozilla/5.0",
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(h.audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(h.audit.events))
	}

	event := h.audit.events[0]

	if event.Type != audit.EventUserRegistered {
		t.Errorf("event type = %q, want %q", event.Type, audit.EventUserRegistered)
	}

	if !event.Success {
		t.Error("a successful registration must be audited as a success")
	}

	if event.UserID == nil || event.UserID.String() != result.ID {
		t.Errorf("event user ID = %v, want %q", event.UserID, result.ID)
	}

	if event.Email != "bayu@example.com" {
		t.Errorf("event email = %q, want the normalized address", event.Email)
	}

	if event.IPAddress != "203.0.113.10" {
		t.Errorf("event IP = %q, want %q", event.IPAddress, "203.0.113.10")
	}

	if event.UserAgent != "Mozilla/5.0" {
		t.Errorf("event user agent = %q, want %q", event.UserAgent, "Mozilla/5.0")
	}
}

// A rejected registration (duplicate email, weak password, ...) must not be
// audited as a USER_REGISTERED success — nothing was actually created.
func TestRegisterService_Handle_DoesNotAuditAFailedRegistration(t *testing.T) {

	h := newHarness()

	h.users.findByEmail = func(ctx context.Context, email string) (*user.User, error) {
		return &user.User{ID: uuid.New(), Email: email}, nil
	}

	_, err := h.service().Handle(
		context.Background(),
		Command{
			Email:    "taken@example.com",
			Password: "Str0ng!Passphrase",
		},
	)

	if !errors.Is(err, errs.ErrUserAlreadyExists) {
		t.Fatalf("error = %v, want %v", err, errs.ErrUserAlreadyExists)
	}

	if len(h.audit.events) != 0 {
		t.Errorf("audit events = %d, want 0 on a failed registration", len(h.audit.events))
	}
}

func TestRegisterService_Handle_RateLimiting(t *testing.T) {

	t.Run("rejects a request over the IP limit", func(t *testing.T) {

		h := newHarness()

		h.tracker.blocked = true

		result, err := h.service().Handle(
			context.Background(),
			Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},
		)

		if !errors.Is(err, errs.ErrTooManyRequests) {
			t.Fatalf("error = %v, want %v", err, errs.ErrTooManyRequests)
		}

		if result != nil {
			t.Errorf("result = %+v, want nil on error", result)
		}
	})

	t.Run("propagates a rate limiter failure", func(t *testing.T) {

		h := newHarness()

		h.tracker.checkErr = errors.New("redis unreachable")

		_, err := h.service().Handle(
			context.Background(),
			Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},
		)

		if err == nil {
			t.Fatal("expected an error when the rate limiter is unreachable")
		}
	})

	// The counter must advance even when the attempt goes on to fail for an
	// unrelated reason (weak password, duplicate email, ...) — an attacker
	// probing many candidate emails, each rejected as already-registered,
	// is exactly the pattern this limiter exists to cap.
	t.Run("counts an attempt that fails validation afterward", func(t *testing.T) {

		h := newHarness()

		h.users.findByEmail = func(ctx context.Context, email string) (*user.User, error) {
			return &user.User{ID: uuid.New(), Email: email}, nil
		}

		_, err := h.service().Handle(
			context.Background(),
			Command{
				Email:    "taken@example.com",
				Password: "Str0ng!Passphrase",
			},
		)

		if !errors.Is(err, errs.ErrUserAlreadyExists) {
			t.Fatalf("error = %v, want %v", err, errs.ErrUserAlreadyExists)
		}

		if len(h.tracker.failures) != 1 {
			t.Errorf("rate limit counter incremented %d times, want 1", len(h.tracker.failures))
		}
	})
}
