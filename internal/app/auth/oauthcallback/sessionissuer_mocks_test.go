package oauthcallback

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	domainRefresh "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/domain/token"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

// The mocks in this file are exactly what sessionissuer.Issuer needs —
// login/mocks_test.go carries the identical set for the same reason:
// the transactional device-slot/session/refresh-token logic they
// exercise lives in one place (app/auth/sessionissuer) shared by both
// login and this package, not reimplemented here.

//
// Session repository
//

type mockSessionRepository struct {
	mu sync.Mutex

	created []session.Session

	createErr error

	stored map[uuid.UUID]*session.Session

	findActiveByDeviceErr error

	lockDeviceErr error

	lockDeviceCalls int

	revokeErr error

	revokedSessions []uuid.UUID
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

	m.mu.Lock()
	defer m.mu.Unlock()

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
	mu sync.Mutex

	created []domainRefresh.Token

	createErr error
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

	m.mu.Lock()
	defer m.mu.Unlock()

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

	return nil
}

func (m *mockRefreshRepository) WithTx(
	tx pgx.Tx,
) domainRefresh.Repository {

	return m
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
