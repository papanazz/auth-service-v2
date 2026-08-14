package resendverification

import (
	"context"
	"sync"
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

	snapshot := *m.account

	return &snapshot, nil
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

func (m *mockUserRepository) WithTx(
	tx pgx.Tx,
) user.Repository {

	return m
}

//
// Verification token repository
//

type mockVerificationRepository struct {
	mu sync.Mutex

	activeByUser map[uuid.UUID]*verification.Token

	findActiveErr error

	created []verification.Token

	createErr error
}

func newMockVerificationRepository() *mockVerificationRepository {

	return &mockVerificationRepository{
		activeByUser: map[uuid.UUID]*verification.Token{},
	}
}

func (m *mockVerificationRepository) Create(
	ctx context.Context,
	token verification.Token,
) error {

	if m.createErr != nil {
		return m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

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

	if m.findActiveErr != nil {
		return nil, m.findActiveErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	found, ok := m.activeByUser[userID]

	if !ok {
		return nil, errs.ErrVerificationTokenNotFound
	}

	snapshot := *found

	return &snapshot, nil
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

func (m *mockVerificationRepository) createdCount() int {

	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.created)
}

//
// Cache
//

type mockCache struct {
	mu sync.Mutex

	stored map[uuid.UUID]string

	getErr error

	storeErr error
}

func newMockCache() *mockCache {

	return &mockCache{
		stored: map[uuid.UUID]string{},
	}
}

func (m *mockCache) StoreRawToken(
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

	m.stored[tokenID] = rawToken

	return nil
}

func (m *mockCache) GetRawToken(
	ctx context.Context,
	tokenID uuid.UUID,
) (string, bool, error) {

	if m.getErr != nil {
		return "", false, m.getErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	value, ok := m.stored[tokenID]

	return value, ok, nil
}

//
// Generator and hasher
//

type mockGenerator struct {
	value string

	err error
}

func (m mockGenerator) Generate() (string, error) {

	if m.err != nil {
		return "", m.err
	}

	if m.value == "" {
		return "new-raw-token", nil
	}

	return m.value, nil
}

type mockHasher struct{}

func (mockHasher) Hash(value string) string {
	return "hashed:" + value
}

//
// Email publisher
//

type mockEmailPublisher struct {
	mu sync.Mutex

	published []domainEmail.VerificationEmail

	err error
}

func (m *mockEmailPublisher) PublishVerificationEmail(
	ctx context.Context,
	verificationEmail domainEmail.VerificationEmail,
) error {

	if m.err != nil {
		return m.err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.published = append(m.published, verificationEmail)

	return nil
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

//
// Attempt tracker
//

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

type harness struct {
	users *mockUserRepository

	tokens *mockVerificationRepository

	cache *mockCache

	generator mockGenerator

	emailPublisher *mockEmailPublisher

	audit *mockAuditPublisher

	tracker *mockAttemptTracker

	policy SecurityPolicy

	account user.User
}

func newHarness() *harness {

	h := &harness{
		users: &mockUserRepository{},

		tokens: newMockVerificationRepository(),

		cache: newMockCache(),

		generator: mockGenerator{},

		emailPublisher: &mockEmailPublisher{},

		audit: &mockAuditPublisher{},

		tracker: &mockAttemptTracker{},

		policy: SecurityPolicy{

			IP: security.LimitPolicy{

				Type: security.PolicyResendVerification,

				Limit: 10,

				Window: time.Minute,
			},

			TokenTTL: 24 * time.Hour,
		},
	}

	h.account = user.User{
		ID: uuid.New(),

		Email: "bayu@example.com",

		Status: user.StatusActive,

		CreatedAt: time.Now().UTC(),
	}

	h.users.account = &h.account

	return h
}

func (h *harness) service() *Service {

	return NewService(
		h.users,
		h.tokens,
		h.cache,
		h.generator,
		mockHasher{},
		h.emailPublisher,
		h.audit,
		h.tracker,
		h.policy,
	)
}
