package register

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

//
// Mocks
//

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

//
// Tests
//

func TestRegisterService_Handle(t *testing.T) {

	errRepositoryDown := errors.New("connection refused")

	tests := []struct {
		name string

		cmd Command

		repository *mockUserRepository

		hasher mockHasher

		policy mockPolicy

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

			repository: &mockUserRepository{},

			wantEmail: "bayu@example.com",
		},
		{
			name: "normalizes email casing and surrounding space",

			cmd: Command{
				Email:    "  BaYu@Example.COM  ",
				Password: "Str0ng!Passphrase",
			},

			repository: &mockUserRepository{},

			wantEmail: "bayu@example.com",
		},
		{
			name: "rejects a malformed email",

			cmd: Command{
				Email:    "not-an-email",
				Password: "Str0ng!Passphrase",
			},

			repository: &mockUserRepository{},

			wantErr: errs.ErrInvalidEmail,
		},
		{
			name: "rejects a password the policy refuses",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "short",
			},

			repository: &mockUserRepository{},

			policy: mockPolicy{err: errs.ErrWeakPassword},

			wantErr: errs.ErrWeakPassword,
		},
		{
			name: "rejects an email that already exists",

			cmd: Command{
				Email:    "taken@example.com",
				Password: "Str0ng!Passphrase",
			},

			repository: &mockUserRepository{
				findByEmail: func(
					ctx context.Context,
					email string,
				) (*user.User, error) {

					return &user.User{
						ID:    uuid.New(),
						Email: email,
					}, nil
				},
			},

			wantErr: errs.ErrUserAlreadyExists,
		},
		{
			name: "propagates an unexpected lookup failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			repository: &mockUserRepository{
				findByEmail: func(
					ctx context.Context,
					email string,
				) (*user.User, error) {

					return nil, errRepositoryDown
				},
			},

			wantErr: errRepositoryDown,
		},
		{
			name: "propagates a hashing failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			repository: &mockUserRepository{},

			hasher: mockHasher{err: errRepositoryDown},

			wantErr: errRepositoryDown,
		},
		{
			name: "propagates a create failure",

			cmd: Command{
				Email:    "bayu@example.com",
				Password: "Str0ng!Passphrase",
			},

			repository: &mockUserRepository{
				createErr: errRepositoryDown,
			},

			wantErr: errRepositoryDown,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			service := NewService(
				tt.repository,
				tt.hasher,
				tt.policy,
				&mockAuditPublisher{},
			)

			result, err := service.Handle(
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

	repository := &mockUserRepository{}

	service := NewService(
		repository,
		mockHasher{},
		mockPolicy{},
		&mockAuditPublisher{},
	)

	const plaintext = "Str0ng!Passphrase"

	result, err := service.Handle(
		context.Background(),
		Command{
			Email:    "  BaYu@Example.COM ",
			Password: plaintext,
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repository.created == nil {
		t.Fatal("account was never passed to the repository")
	}

	stored := *repository.created

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

func TestRegisterService_Handle_RecordsAuditTrail(t *testing.T) {

	repository := &mockUserRepository{}

	auditPublisher := &mockAuditPublisher{}

	service := NewService(
		repository,
		mockHasher{},
		mockPolicy{},
		auditPublisher,
	)

	result, err := service.Handle(
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

	if len(auditPublisher.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(auditPublisher.events))
	}

	event := auditPublisher.events[0]

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

	auditPublisher := &mockAuditPublisher{}

	service := NewService(
		&mockUserRepository{
			findByEmail: func(ctx context.Context, email string) (*user.User, error) {
				return &user.User{ID: uuid.New(), Email: email}, nil
			},
		},
		mockHasher{},
		mockPolicy{},
		auditPublisher,
	)

	_, err := service.Handle(
		context.Background(),
		Command{
			Email:    "taken@example.com",
			Password: "Str0ng!Passphrase",
		},
	)

	if !errors.Is(err, errs.ErrUserAlreadyExists) {
		t.Fatalf("error = %v, want %v", err, errs.ErrUserAlreadyExists)
	}

	if len(auditPublisher.events) != 0 {
		t.Errorf("audit events = %d, want 0 on a failed registration", len(auditPublisher.events))
	}
}
