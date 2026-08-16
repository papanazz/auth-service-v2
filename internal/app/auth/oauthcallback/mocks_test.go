package oauthcallback

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	domainEmail "github.com/papanazz/auth-service-v2/internal/domain/email"
	"github.com/papanazz/auth-service-v2/internal/domain/oauth"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

//
// Logger
//

type loggedError struct {
	message string

	err error

	metadata map[string]any
}

// mockLogger satisfies domain/logging.Logger — every best-effort call
// this service swallows now logs through this instead of silently
// discarding the error, so tests can assert it actually happened.
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
// oauth.Exchanger
//

type mockExchanger struct {
	identity oauth.Identity

	err error

	// seen carries the (code, verifier) pair Exchange was actually
	// called with, so a test can assert the state payload's verifier
	// made it all the way through, not just some verifier.
	seenCode string

	seenVerifier string
}

func (m *mockExchanger) AuthCodeURL(
	state string,
	codeChallenge string,
) string {

	return ""
}

func (m *mockExchanger) Exchange(
	ctx context.Context,
	code string,
	codeVerifier string,
) (oauth.Identity, error) {

	m.seenCode = code

	m.seenVerifier = codeVerifier

	if m.err != nil {
		return oauth.Identity{}, m.err
	}

	return m.identity, nil
}

//
// oauth.StateStore
//

type mockStateStore struct {
	payload oauth.StatePayload

	found bool

	consumeErr error

	consumeCalls []string
}

func (m *mockStateStore) Store(
	ctx context.Context,
	state string,
	payload oauth.StatePayload,
	ttl time.Duration,
) error {

	return nil
}

func (m *mockStateStore) Consume(
	ctx context.Context,
	state string,
) (oauth.StatePayload, bool, error) {

	m.consumeCalls = append(m.consumeCalls, state)

	if m.consumeErr != nil {
		return oauth.StatePayload{}, false, m.consumeErr
	}

	return m.payload, m.found, nil
}

//
// oauth.Repository
//

type mockOAuthRepository struct {
	mu sync.Mutex

	link *oauth.Link

	findErr error

	created []oauth.Link

	createErr error
}

func (m *mockOAuthRepository) FindByProviderID(
	ctx context.Context,
	provider oauth.Provider,
	providerUserID string,
) (*oauth.Link, error) {

	if m.findErr != nil {
		return nil, m.findErr
	}

	if m.link == nil {
		return nil, errs.ErrOAuthIdentityNotFound
	}

	return m.link, nil
}

func (m *mockOAuthRepository) Create(
	ctx context.Context,
	link oauth.Link,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createErr != nil {
		return m.createErr
	}

	m.created = append(m.created, link)

	return nil
}

func (m *mockOAuthRepository) WithTx(
	tx pgx.Tx,
) oauth.Repository {

	return m
}

//
// user.Repository
//

type mockUserRepository struct {
	mu sync.Mutex

	findByEmailFn func(ctx context.Context, email string) (*user.User, error)

	findByIDFn func(ctx context.Context, id uuid.UUID) (*user.User, error)

	created *user.User

	createErr error

	updateLastLoginAtErr error

	updateLastLoginAtCalls []uuid.UUID
}

func (m *mockUserRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*user.User, error) {

	if m.findByEmailFn != nil {
		return m.findByEmailFn(ctx, email)
	}

	return nil, errs.ErrUserNotFound
}

func (m *mockUserRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (*user.User, error) {

	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}

	return nil, errs.ErrUserNotFound
}

func (m *mockUserRepository) Create(
	ctx context.Context,
	account user.User,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

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
// verification.Repository / Cache / Generator / Hasher
//

type mockVerificationRepository struct {
	mu sync.Mutex

	created []verification.Token

	createErr error
}

func (m *mockVerificationRepository) Create(
	ctx context.Context,
	token verification.Token,
) error {

	m.mu.Lock()
	defer m.mu.Unlock()

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

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.storeErr != nil {
		return m.storeErr
	}

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

//
// domain/email.Publisher
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

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return m.err
	}

	m.published = append(m.published, verificationEmail)

	return nil
}

//
// audit.Publisher
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
