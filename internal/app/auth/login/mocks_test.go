package login

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/auth/sessionissuer"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	domainRefresh "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/security"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

// errBackendDown stands in for any unexpected infrastructure failure.
var errBackendDown = errors.New("connection refused")

type loggedError struct {
	message string

	err error

	metadata map[string]any
}

// mockLogger satisfies domain/logging.Logger — every best-effort call
// login swallows now logs through this instead of silently discarding
// the error, so tests can assert it actually happened.
type mockLogger struct {
	mu sync.Mutex

	errors []loggedError
}

func (m *mockLogger) Error(
	ctx context.Context,
	message string,
	err error,
	metadata map[string]any,
) {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.errors = append(m.errors, loggedError{
		message: message,

		err: err,

		metadata: metadata,
	})
}

//
// Transaction manager
//
// The repositories below ignore the tx handle, so passing nil is safe and
// keeps the mock honest about what it does: run the callback, surface errors.
//
// A real transaction serializes on Postgres's transaction-scoped advisory
// lock (see LockDeviceSlot), so two concurrent transactions touching the same
// device never interleave their reads and writes. This mock over-approximates
// that with a single mutex held for the whole callback — coarser than the
// real per-key lock, but sufficient to test the login service's
// decide-then-act sequence under real concurrency.
//

type mockTransactionManager struct {
	mu sync.Mutex

	err error

	calls int
}

func (m *mockTransactionManager) WithinTransaction(
	ctx context.Context,
	fn func(tx pgx.Tx) error,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++

	if m.err != nil {
		return m.err
	}

	return fn(nil)
}

//
// User repository
//

type mockUserRepository struct {
	mu sync.Mutex

	account *user.User

	findErr error

	updateLastLoginAtErr error

	updateLastLoginAtCalls []uuid.UUID
}

func (m *mockUserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*user.User, error) {

	if m.findErr != nil {
		return nil, m.findErr
	}

	if m.account == nil {
		return nil, errs.ErrUserNotFound
	}

	return m.account, nil
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

func (m *mockUserRepository) UpdateLastLoginAt(
	ctx context.Context,
	userID uuid.UUID,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.updateLastLoginAtCalls = append(m.updateLastLoginAtCalls, userID)

	return m.updateLastLoginAtErr
}

func (m *mockUserRepository) WithTx(
	tx pgx.Tx,
) user.Repository {

	return m
}

//
// Session repository
//

type mockSessionRepository struct {
	created []session.Session

	createErr error

	stored map[uuid.UUID]*session.Session

	findErr error

	findActiveByDeviceErr error

	lastRefreshedCalls []uuid.UUID

	revokedSessions []uuid.UUID

	revokedReasons []session.RevokeReason

	revokeErr error

	lockDeviceErr error

	lockDeviceCalls int
}

func newMockSessionRepository() *mockSessionRepository {

	return &mockSessionRepository{
		stored: map[uuid.UUID]*session.Session{},
	}
}

func (m *mockSessionRepository) Create(
	ctx context.Context,
	s session.Session,
) error {

	if m.createErr != nil {
		return m.createErr
	}

	m.created = append(m.created, s)

	m.stored[s.ID] = &s

	return nil
}

func (m *mockSessionRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (*session.Session, error) {

	if m.findErr != nil {
		return nil, m.findErr
	}

	found, ok := m.stored[id]

	if !ok {
		return nil, errs.ErrSessionNotFound
	}

	return found, nil
}

func (m *mockSessionRepository) FindActiveByID(
	ctx context.Context,
	id uuid.UUID,
) (*session.Session, error) {

	return m.FindByID(ctx, id)
}

func (m *mockSessionRepository) FindActiveByUserAndDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) (*session.Session, error) {

	if m.findActiveByDeviceErr != nil {
		return nil, m.findActiveByDeviceErr
	}

	for _, s := range m.stored {

		if s.UserID == userID &&
			s.DeviceID == deviceID &&
			s.RevokedAt == nil {

			return s, nil
		}
	}

	return nil, errs.ErrSessionNotFound
}

// LockDeviceSlot is a no-op here: real serialization for these tests comes
// from mockTransactionManager holding its mutex for the whole transaction,
// which is what the real advisory lock achieves in production. This just
// tracks the call and lets tests inject a failure.
func (m *mockSessionRepository) LockDeviceSlot(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) error {

	m.lockDeviceCalls++

	if m.lockDeviceErr != nil {
		return m.lockDeviceErr
	}

	return nil
}

func (m *mockSessionRepository) Revoke(
	ctx context.Context,
	id uuid.UUID,
	reason session.RevokeReason,
) error {

	if m.revokeErr != nil {
		return m.revokeErr
	}

	m.revokedSessions = append(m.revokedSessions, id)

	m.revokedReasons = append(m.revokedReasons, reason)

	if found, ok := m.stored[id]; ok && found.RevokedAt == nil {

		now := time.Now()

		found.RevokedAt = &now

		found.RevokedReason = &reason
	}

	return nil
}

func (m *mockSessionRepository) UpdateLastUsedAt(
	ctx context.Context,
	id uuid.UUID,
) error {

	return nil
}

func (m *mockSessionRepository) UpdateLastRefreshedAt(
	ctx context.Context,
	id uuid.UUID,
) error {

	m.lastRefreshedCalls = append(m.lastRefreshedCalls, id)

	return nil
}

func (m *mockSessionRepository) WithTx(
	tx sqlc.DBTX,
) session.Repository {

	return m
}

//
// Refresh token repository
//

type mockRefreshRepository struct {
	created []domainRefresh.Token

	createErr error

	revokedFamilies []uuid.UUID
}

func (m *mockRefreshRepository) FindByHash(
	ctx context.Context,
	hash string,
) (*domainRefresh.Token, error) {

	return nil, errs.ErrInvalidRefreshToken
}

func (m *mockRefreshRepository) Create(
	ctx context.Context,
	t domainRefresh.Token,
) error {

	if m.createErr != nil {
		return m.createErr
	}

	m.created = append(m.created, t)

	return nil
}

func (m *mockRefreshRepository) Consume(
	ctx context.Context,
	id uuid.UUID,
) (bool, error) {

	return true, nil
}

func (m *mockRefreshRepository) RevokeFamily(
	ctx context.Context,
	familyID uuid.UUID,
	reason domainRefresh.RevokeReason,
) error {

	m.revokedFamilies = append(m.revokedFamilies, familyID)

	return nil
}

func (m *mockRefreshRepository) WithTx(
	tx pgx.Tx,
) domainRefresh.Repository {

	return m
}

//
// Password verifier
//

type mockVerifier struct {
	mu sync.Mutex

	err error

	// hashes seen, so a test can assert the dummy-hash enumeration defense ran
	seen []string
}

func (m *mockVerifier) Verify(hash string, password string) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.seen = append(m.seen, hash)

	return m.err
}

//
// Access token service
//

type mockAccessTokenService struct {
	mu sync.Mutex

	err error

	claims []token.Claims
}

func (m *mockAccessTokenService) Generate(
	claims token.Claims,
) (token.AccessToken, error) {

	if m.err != nil {
		return token.AccessToken{}, m.err
	}

	m.mu.Lock()
	m.claims = append(m.claims, claims)
	m.mu.Unlock()

	now := time.Now()

	return token.AccessToken{
		Token:     "access-token",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	}, nil
}

//
// Refresh token generator and hasher
//

type mockRefreshGenerator struct {
	value string

	err error
}

func (m mockRefreshGenerator) Generate() (string, error) {

	if m.err != nil {
		return "", m.err
	}

	if m.value == "" {
		return "raw-refresh-token", nil
	}

	return m.value, nil
}

type mockRefreshHasher struct{}

func (mockRefreshHasher) Hash(value string) string {
	return "hashed:" + value
}

//
// Audit publisher
//

type mockAuditPublisher struct {
	mu sync.Mutex

	events []audit.Event
}

func (m *mockAuditPublisher) Publish(
	ctx context.Context,
	event audit.Event,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.events = append(m.events, event)

	return nil
}

func (m *mockAuditPublisher) types() []audit.EventType {

	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]audit.EventType, 0, len(m.events))

	for _, e := range m.events {
		out = append(out, e.Type)
	}

	return out
}

//
// Attempt tracker
//

type mockAttemptTracker struct {
	mu sync.Mutex

	// keys that are over the limit
	blocked map[string]bool

	checkErr error

	failures []string

	resets []string
}

func newMockAttemptTracker() *mockAttemptTracker {

	return &mockAttemptTracker{
		blocked: map[string]bool{},
	}
}

func (m *mockAttemptTracker) Check(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) (bool, error) {

	if m.checkErr != nil {
		return false, m.checkErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return !m.blocked[key], nil
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

	m.mu.Lock()
	defer m.mu.Unlock()

	m.resets = append(m.resets, key)

	return nil
}

//
// Builder
//

type harness struct {
	transaction *mockTransactionManager

	users *mockUserRepository

	sessions *mockSessionRepository

	refreshTokens *mockRefreshRepository

	passwords *mockVerifier

	accessTokens *mockAccessTokenService

	generator mockRefreshGenerator

	audit *mockAuditPublisher

	tracker *mockAttemptTracker

	logger *mockLogger

	policy SecurityPolicy

	// sessionIssuerPolicy carries what used to be part of SecurityPolicy
	// (RefreshTokenTTL, SessionTTL, DeviceGracePeriod) before
	// sessionissuer.Issuer was extracted — see docs/oauth.md. service()
	// builds a real Issuer from this harness's own mocks, so every
	// existing assertion against h.sessions/h.refreshTokens/h.transaction
	// still observes the identical transactional behavior, just reached
	// through the Issuer instead of inline login code.
	sessionIssuerPolicy sessionissuer.Policy
}

func newHarness() *harness {

	return &harness{
		transaction: &mockTransactionManager{},

		users: &mockUserRepository{},

		sessions: newMockSessionRepository(),

		refreshTokens: &mockRefreshRepository{},

		passwords: &mockVerifier{},

		accessTokens: &mockAccessTokenService{},

		generator: mockRefreshGenerator{},

		audit: &mockAuditPublisher{},

		tracker: newMockAttemptTracker(),

		logger: &mockLogger{},

		policy: SecurityPolicy{
			IP: security.LimitPolicy{
				Type:   security.PolicyLoginAttempt,
				Limit:  10,
				Window: time.Minute,
			},

			Credential: security.LimitPolicy{
				Type:   security.PolicyLoginAttempt,
				Limit:  5,
				Window: 15 * time.Minute,
			},
		},

		sessionIssuerPolicy: sessionissuer.Policy{

			RefreshTokenTTL: 30 * 24 * time.Hour,

			SessionTTL: 90 * 24 * time.Hour,

			DeviceGracePeriod: 5 * time.Minute,
		},
	}
}

func (h *harness) service() *LoginService {

	issuer :=
		sessionissuer.NewIssuer(
			h.transaction,
			h.sessions,
			h.refreshTokens,
			h.accessTokens,
			h.generator,
			mockRefreshHasher{},
			h.sessionIssuerPolicy,
		)

	return NewService(
		h.users,
		h.passwords,
		issuer,
		h.audit,
		h.tracker,
		h.logger,
		h.policy,
	)
}

func passwordHashPtr(hash string) *string {
	return &hash
}

// activeAccount registers a login-capable account with the given password hash.
func (h *harness) activeAccount(email string) *user.User {

	account := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHashPtr("hashed:correct-password"),
		Status:       user.StatusActive,
	}

	h.users.account = account

	return account
}

// lockedAccount registers an account whose credentials are correct but
// whose status blocks CanLogin — e.g. a lockout from repeated failures, or
// an admin action. Correct password + blocked status is exactly the state
// the account-status gate exists to catch.
func (h *harness) lockedAccount(email string) *user.User {

	account := h.activeAccount(email)

	lockedUntil := time.Now().Add(time.Hour)

	account.Status = user.StatusLocked

	account.LockedUntil = &lockedUntil

	return account
}

// activeSessionForDevice seeds an already-active session for the given
// account/device, created at createdAt, so device-collision tests can
// exercise the supersede/reject fork without going through a real login.
func (h *harness) activeSessionForDevice(
	userID uuid.UUID,
	deviceID string,
	createdAt time.Time,
) *session.Session {

	existing := &session.Session{
		ID: uuid.New(),

		UserID: userID,

		DeviceID: deviceID,

		ExpiresAt: createdAt.Add(90 * 24 * time.Hour),

		CreatedAt: createdAt,
	}

	h.sessions.stored[existing.ID] = existing

	return existing
}
