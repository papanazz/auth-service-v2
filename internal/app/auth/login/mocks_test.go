package login

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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

//
// Transaction manager
//
// The repositories below ignore the tx handle, so passing nil is safe and
// keeps the mock honest about what it does: run the callback, surface errors.
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

//
// User repository
//

type mockUserRepository struct {
	account *user.User

	findErr error
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

//
// Session repository
//

type mockSessionRepository struct {
	created []session.Session

	createErr error

	stored map[uuid.UUID]*session.Session

	findErr error

	lastRefreshedCalls []uuid.UUID
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

func (m *mockSessionRepository) Revoke(
	ctx context.Context,
	id uuid.UUID,
	reason session.RevokeReason,
) error {

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
	err error

	// hashes seen, so a test can assert the dummy-hash enumeration defense ran
	seen []string
}

func (m *mockVerifier) Verify(hash string, password string) error {

	m.seen = append(m.seen, hash)

	return m.err
}

//
// Access token service
//

type mockAccessTokenService struct {
	err error

	claims []token.Claims
}

func (m *mockAccessTokenService) Generate(
	claims token.Claims,
) (token.AccessToken, error) {

	if m.err != nil {
		return token.AccessToken{}, m.err
	}

	m.claims = append(m.claims, claims)

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
	events []audit.Event
}

func (m *mockAuditPublisher) Publish(
	ctx context.Context,
	event audit.Event,
) error {

	m.events = append(m.events, event)

	return nil
}

func (m *mockAuditPublisher) types() []audit.EventType {

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

	return !m.blocked[key], nil
}

func (m *mockAttemptTracker) RecordFailure(
	ctx context.Context,
	key string,
	policy security.LimitPolicy,
) error {

	m.failures = append(m.failures, key)

	return nil
}

func (m *mockAttemptTracker) Reset(
	ctx context.Context,
	key string,
) error {

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

	policy SecurityPolicy
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

			RefreshTokenTTL: 30 * 24 * time.Hour,

			SessionTTL: 90 * 24 * time.Hour,
		},
	}
}

func (h *harness) service() *LoginService {

	return NewService(
		h.transaction,
		h.users,
		h.sessions,
		h.refreshTokens,
		h.passwords,
		h.accessTokens,
		h.generator,
		mockRefreshHasher{},
		h.audit,
		h.tracker,
		h.policy,
	)
}

// activeAccount registers a login-capable account with the given password hash.
func (h *harness) activeAccount(email string) *user.User {

	account := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: "hashed:correct-password",
		Status:       user.StatusActive,
	}

	h.users.account = account

	return account
}
