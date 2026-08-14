package verifyemail

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
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
// Verification token repository
//

type mockVerificationRepository struct {
	tokens map[string]*verification.Token

	findErr error

	// consumeReturnsFalse simulates losing the compare-and-swap to a
	// concurrent winner, regardless of the token's own ConsumedAt.
	consumeReturnsFalse bool

	consumeErr error

	consumedIDs []uuid.UUID
}

func newMockVerificationRepository() *mockVerificationRepository {

	return &mockVerificationRepository{
		tokens: map[string]*verification.Token{},
	}
}

func (m *mockVerificationRepository) Create(
	ctx context.Context,
	token verification.Token,
) error {

	m.tokens[token.Hash] = &token

	return nil
}

func (m *mockVerificationRepository) FindByHash(
	ctx context.Context,
	hash string,
) (*verification.Token, error) {

	if m.findErr != nil {
		return nil, m.findErr
	}

	found, ok := m.tokens[hash]

	if !ok {
		return nil, errs.ErrVerificationTokenNotFound
	}

	snapshot := *found

	return &snapshot, nil
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

	if m.consumeErr != nil {
		return false, m.consumeErr
	}

	m.consumedIDs = append(m.consumedIDs, id)

	if m.consumeReturnsFalse {
		return false, nil
	}

	return true, nil
}

func (m *mockVerificationRepository) WithTx(
	tx pgx.Tx,
) verification.Repository {

	return m
}

//
// User repository
//

type mockUserRepository struct {
	account *user.User

	findErr error

	markVerifiedErr error

	markVerifiedCalls int
}

func (m *mockUserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*user.User, error) {

	return nil, errs.ErrUserNotFound
}

func (m *mockUserRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
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

	if m.markVerifiedErr != nil {
		return m.markVerifiedErr
	}

	m.markVerifiedCalls++

	if m.account != nil {

		m.account.EmailVerifiedAt = &verifiedAt

		m.account.Status = status
	}

	return nil
}

func (m *mockUserRepository) WithTx(
	tx pgx.Tx,
) user.Repository {

	return m
}

//
// Hasher
//

type mockHasher struct{}

func (mockHasher) Hash(value string) string {
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

//
// Harness
//

type harness struct {
	transaction *mockTransactionManager

	tokens *mockVerificationRepository

	users *mockUserRepository

	audit *mockAuditPublisher

	rawToken string

	token verification.Token

	account user.User
}

// newHarness builds a service with one unconsumed, unexpired
// verification token for one unverified account — the state
// registration leaves behind.
func newHarness() *harness {

	h := &harness{
		transaction: &mockTransactionManager{},

		tokens: newMockVerificationRepository(),

		audit: &mockAuditPublisher{},
	}

	now := time.Now().UTC()

	h.account = user.User{
		ID: uuid.New(),

		Email: "bayu@example.com",

		Status: user.StatusActive,

		CreatedAt: now,
	}

	h.users = &mockUserRepository{account: &h.account}

	h.rawToken = "raw-verification-token"

	h.token = verification.Token{
		ID: uuid.New(),

		UserID: h.account.ID,

		Hash: mockHasher{}.Hash(h.rawToken),

		ExpiresAt: now.Add(24 * time.Hour),

		CreatedAt: now,
	}

	h.tokens.tokens[h.token.Hash] = &h.token

	return h
}

func (h *harness) service() *Service {

	return NewService(
		h.transaction,
		h.tokens,
		h.users,
		mockHasher{},
		h.audit,
	)
}
