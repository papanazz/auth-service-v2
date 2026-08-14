package logout

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
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var errBackendDown = errors.New("connection refused")

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

type mockRefreshRepository struct {
	mu sync.Mutex

	tokens map[string]*domainRefresh.Token

	revokedFamilies []domainRefresh.RevokeReason

	revokeFamilyErr error

	findErr error
}

func newMockRefreshRepository() *mockRefreshRepository {

	return &mockRefreshRepository{
		tokens: map[string]*domainRefresh.Token{},
	}
}

func (m *mockRefreshRepository) store(t domainRefresh.Token) {

	m.tokens[t.Hash] = &t
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

	snapshot := *found

	return &snapshot, nil
}

func (m *mockRefreshRepository) Create(
	ctx context.Context,
	t domainRefresh.Token,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[t.Hash] = &t

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

	if m.revokeFamilyErr != nil {
		return m.revokeFamilyErr
	}

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

//
// Session repository
//

type mockSessionRepository struct {
	mu sync.Mutex

	stored map[uuid.UUID]*session.Session

	findErr error

	revokeErr error

	revokedSessions []session.RevokeReason
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

func (m *mockSessionRepository) Revoke(
	ctx context.Context,
	id uuid.UUID,
	reason session.RevokeReason,
) error {

	if m.revokeErr != nil {
		return m.revokeErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokedSessions = append(m.revokedSessions, reason)

	if found, ok := m.stored[id]; ok {

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

	return nil
}

func (m *mockSessionRepository) WithTx(
	tx sqlc.DBTX,
) session.Repository {

	return m
}

func (m *mockSessionRepository) revocationCount() int {

	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.revokedSessions)
}

//
// Refresh token hasher
//

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

func (m *mockAuditPublisher) countOf(t audit.EventType, success bool) int {

	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0

	for _, e := range m.events {
		if e.Type == t && e.Success == success {
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

	audit *mockAuditPublisher

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

		ExpiresAt: now.Add(720 * time.Hour),

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
		mockRefreshHasher{},
		h.audit,
	)
}
