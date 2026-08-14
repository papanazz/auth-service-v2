package refresh

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	domainRefresh "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var errBackendDown = errors.New("connection refused")

const testRefreshTTL = 720 * time.Hour

//
// Transaction manager
//

type mockTransactionManager struct {
	err error
}

func (m *mockTransactionManager) WithinTransaction(
	ctx context.Context,
	fn func(tx pgx.Tx) error,
) error {

	if m.err != nil {
		return m.err
	}

	return fn(nil)
}

//
// Refresh token repository
//
// Consume mirrors the production SQL:
//
//	UPDATE refresh_tokens SET consumed_at = NOW()
//	WHERE id = $1 AND consumed_at IS NULL
//
// It is a compare-and-swap, so only the first caller for a given id observes
// a row change. The mutex stands in for the row lock Postgres would take.
//

type mockRefreshRepository struct {
	mu sync.Mutex

	tokens map[string]*domainRefresh.Token

	byID map[uuid.UUID]*domainRefresh.Token

	created []domainRefresh.Token

	revokedFamilies []domainRefresh.RevokeReason

	findErr error

	createErr error

	consumeErr error
}

func newMockRefreshRepository() *mockRefreshRepository {

	return &mockRefreshRepository{
		tokens: map[string]*domainRefresh.Token{},
		byID:   map[uuid.UUID]*domainRefresh.Token{},
	}
}

func (m *mockRefreshRepository) store(t domainRefresh.Token) {

	m.tokens[t.Hash] = &t

	m.byID[t.ID] = &t
}

func (m *mockRefreshRepository) FindByHash(
	ctx context.Context,
	hash string,
) (*domainRefresh.Token, error) {

	if m.findErr != nil {
		return nil, m.findErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	found, ok := m.tokens[hash]

	if !ok {
		return nil, errs.ErrInvalidRefreshToken
	}

	// Return a copy so callers cannot mutate stored state by accident.
	snapshot := *found

	return &snapshot, nil
}

func (m *mockRefreshRepository) Create(
	ctx context.Context,
	t domainRefresh.Token,
) error {

	if m.createErr != nil {
		return m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.created = append(m.created, t)

	m.tokens[t.Hash] = &t

	m.byID[t.ID] = &t

	return nil
}

func (m *mockRefreshRepository) Consume(
	ctx context.Context,
	id uuid.UUID,
) (bool, error) {

	if m.consumeErr != nil {
		return false, m.consumeErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	found, ok := m.byID[id]

	if !ok {
		return false, nil
	}

	if found.ConsumedAt != nil {
		return false, nil
	}

	now := time.Now()

	found.ConsumedAt = &now

	return true, nil
}

func (m *mockRefreshRepository) RevokeFamily(
	ctx context.Context,
	familyID uuid.UUID,
	reason domainRefresh.RevokeReason,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokedFamilies = append(m.revokedFamilies, reason)

	return nil
}

func (m *mockRefreshRepository) WithTx(
	tx pgx.Tx,
) domainRefresh.Repository {

	return m
}

func (m *mockRefreshRepository) revocationCount() int {

	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.revokedFamilies)
}

func (m *mockRefreshRepository) createdCount() int {

	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.created)
}

//
// Session repository
//

type mockSessionRepository struct {
	mu sync.Mutex

	stored map[uuid.UUID]*session.Session

	findErr error

	refreshedCalls int
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

	m.mu.Lock()
	defer m.mu.Unlock()

	found, ok := m.stored[id]

	if !ok {
		return nil, errs.ErrSessionNotFound
	}

	snapshot := *found

	return &snapshot, nil
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

	return nil, errs.ErrSessionNotFound
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

	m.mu.Lock()
	defer m.mu.Unlock()

	m.refreshedCalls++

	return nil
}

func (m *mockSessionRepository) WithTx(
	tx sqlc.DBTX,
) session.Repository {

	return m
}

//
// Supporting mocks
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

// mockRefreshGenerator hands out a distinct value per call so concurrent
// refreshes cannot collide by accident.
type mockRefreshGenerator struct {
	mu sync.Mutex

	n int

	err error
}

func (m *mockRefreshGenerator) Generate() (string, error) {

	if m.err != nil {
		return "", m.err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.n++

	return "raw-token-" + uuid.NewString(), nil
}

type mockRefreshHasher struct{}

func (mockRefreshHasher) Hash(value string) string {
	return "hashed:" + value
}

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

func (m *mockAuditPublisher) typesSeen() []audit.EventType {

	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]audit.EventType, 0, len(m.events))

	for _, e := range m.events {
		out = append(out, e.Type)
	}

	return out
}

func (m *mockAuditPublisher) countOf(t audit.EventType) int {

	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0

	for _, e := range m.events {
		if e.Type == t {
			count++
		}
	}

	return count
}

//
// Harness
//

type harness struct {
	transaction *mockTransactionManager

	refreshTokens *mockRefreshRepository

	sessions *mockSessionRepository

	accessTokens *mockAccessTokenService

	generator *mockRefreshGenerator

	audit *mockAuditPublisher

	// the token handed to the caller, and the session that owns it
	rawToken string

	current domainRefresh.Token

	session session.Session
}

// newHarness builds a service with one active session holding one unconsumed,
// unexpired refresh token — the state login leaves behind.
func newHarness() *harness {

	h := &harness{
		transaction: &mockTransactionManager{},

		refreshTokens: newMockRefreshRepository(),

		sessions: newMockSessionRepository(),

		accessTokens: &mockAccessTokenService{},

		generator: &mockRefreshGenerator{},

		audit: &mockAuditPublisher{},
	}

	now := time.Now().UTC()

	sessionID := uuid.New()

	h.session = session.Session{
		ID: sessionID,

		UserID: uuid.New(),

		DeviceID: "device-1",

		ExpiresAt: now.Add(90 * 24 * time.Hour),

		CreatedAt: now,
	}

	h.sessions.stored[sessionID] = &h.session

	h.rawToken = "raw-token-initial"

	h.current = domainRefresh.Token{
		ID: uuid.New(),

		SessionID: sessionID,

		FamilyID: uuid.New(),

		Hash: mockRefreshHasher{}.Hash(h.rawToken),

		ExpiresAt: now.Add(testRefreshTTL),

		CreatedAt: now,
	}

	h.refreshTokens.store(h.current)

	return h
}

func (h *harness) service() *Service {

	return NewService(
		h.transaction,
		h.refreshTokens,
		h.sessions,
		h.accessTokens,
		h.generator,
		mockRefreshHasher{},
		h.audit,
		testRefreshTTL,
	)
}

// mutateSession applies a change to the stored session.
func (h *harness) mutateSession(fn func(s *session.Session)) {

	stored := h.sessions.stored[h.session.ID]

	fn(stored)
}

// mutateToken applies a change to the stored current token.
func (h *harness) mutateToken(fn func(t *domainRefresh.Token)) {

	stored := h.refreshTokens.tokens[h.current.Hash]

	fn(stored)

	h.refreshTokens.byID[stored.ID] = stored
}
