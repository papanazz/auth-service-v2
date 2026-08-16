package oauthstart

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/oauth"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

var errBackendDown = errors.New("connection refused")

type mockExchanger struct {
	seenState string

	seenChallenge string
}

func (m *mockExchanger) AuthCodeURL(
	state string,
	codeChallenge string,
) string {

	m.seenState = state

	m.seenChallenge = codeChallenge

	return "https://accounts.google.com/o/oauth2/v2/auth?state=" + state
}

func (m *mockExchanger) Exchange(
	ctx context.Context,
	code string,
	codeVerifier string,
) (oauth.Identity, error) {

	return oauth.Identity{}, errors.New("not used by oauthstart")
}

type mockStateStore struct {
	stored map[string]oauth.StatePayload

	storeErr error
}

func newMockStateStore() *mockStateStore {

	return &mockStateStore{
		stored: map[string]oauth.StatePayload{},
	}
}

func (m *mockStateStore) Store(
	ctx context.Context,
	state string,
	payload oauth.StatePayload,
	ttl time.Duration,
) error {

	if m.storeErr != nil {
		return m.storeErr
	}

	m.stored[state] = payload

	return nil
}

func (m *mockStateStore) Consume(
	ctx context.Context,
	state string,
) (oauth.StatePayload, bool, error) {

	payload, ok := m.stored[state]

	return payload, ok, nil
}

type mockGenerator struct {
	state string

	verifier string

	challenge string

	stateErr error

	pkceErr error
}

func (m mockGenerator) GenerateState() (string, error) {

	if m.stateErr != nil {
		return "", m.stateErr
	}

	if m.state == "" {
		return "random-state", nil
	}

	return m.state, nil
}

func (m mockGenerator) GeneratePKCE() (string, string, error) {

	if m.pkceErr != nil {
		return "", "", m.pkceErr
	}

	verifier := m.verifier

	if verifier == "" {
		verifier = "random-verifier"
	}

	challenge := m.challenge

	if challenge == "" {
		challenge = "random-challenge"
	}

	return verifier, challenge, nil
}

func newService(
	exchanger *mockExchanger,
	stateStore *mockStateStore,
	generator mockGenerator,
) *Service {

	return NewService(
		exchanger,
		stateStore,
		generator,
		SecurityPolicy{StateTTL: 10 * time.Minute},
	)
}

func TestService_Handle(t *testing.T) {

	tests := []struct {
		name string

		cmd Command

		wantErr error
	}{
		{
			name: "starts the flow",

			cmd: Command{DeviceID: "device-1", DeviceName: "Pixel 9", DeviceType: session.DeviceWeb},
		},
		{
			name: "rejects an empty device ID",

			cmd: Command{DeviceID: "", DeviceType: session.DeviceWeb},

			wantErr: errs.ErrInvalidRequest,
		},
		{
			name: "rejects a blank device ID",

			cmd: Command{DeviceID: "   ", DeviceType: session.DeviceWeb},

			wantErr: errs.ErrInvalidRequest,
		},
		{
			name: "rejects an invalid device type",

			cmd: Command{DeviceID: "device-1", DeviceType: session.DeviceType("TOASTER")},

			wantErr: errs.ErrInvalidRequest,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {

			svc := newService(&mockExchanger{}, newMockStateStore(), mockGenerator{})

			result, err := svc.Handle(context.Background(), tt.cmd)

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

			if result.AuthURL == "" {
				t.Fatal("expected a non-empty auth URL")
			}
		})
	}
}

func TestService_Handle_StoresTheStatePayload(t *testing.T) {

	stateStore := newMockStateStore()

	svc := newService(
		&mockExchanger{},
		stateStore,
		mockGenerator{state: "the-state", verifier: "the-verifier"},
	)

	_, err := svc.Handle(
		context.Background(),
		Command{DeviceID: "device-1", DeviceName: "Pixel 9", DeviceType: session.DeviceWeb},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	payload, ok := stateStore.stored["the-state"]

	if !ok {
		t.Fatal("state was never stored")
	}

	if payload.CodeVerifier != "the-verifier" {
		t.Errorf("stored code verifier = %q, want %q", payload.CodeVerifier, "the-verifier")
	}

	if payload.DeviceID != "device-1" || payload.DeviceName != "Pixel 9" || payload.DeviceType != session.DeviceWeb {
		t.Errorf("stored device fields = %+v, want the command's own", payload)
	}
}

func TestService_Handle_BuildsTheAuthURLFromStateAndChallenge(t *testing.T) {

	exchanger := &mockExchanger{}

	svc := newService(
		exchanger,
		newMockStateStore(),
		mockGenerator{state: "the-state", challenge: "the-challenge"},
	)

	_, err := svc.Handle(
		context.Background(),
		Command{DeviceID: "device-1", DeviceType: session.DeviceWeb},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if exchanger.seenState != "the-state" {
		t.Errorf("exchanger saw state %q, want %q", exchanger.seenState, "the-state")
	}

	if exchanger.seenChallenge != "the-challenge" {
		t.Errorf("exchanger saw challenge %q, want %q", exchanger.seenChallenge, "the-challenge")
	}
}

func TestService_Handle_PropagatesGeneratorFailures(t *testing.T) {

	t.Run("state generation failure", func(t *testing.T) {

		svc := newService(&mockExchanger{}, newMockStateStore(), mockGenerator{stateErr: errBackendDown})

		_, err := svc.Handle(
			context.Background(),
			Command{DeviceID: "device-1", DeviceType: session.DeviceWeb},
		)

		if !errors.Is(err, errBackendDown) {
			t.Fatalf("error = %v, want %v", err, errBackendDown)
		}
	})

	t.Run("PKCE generation failure", func(t *testing.T) {

		svc := newService(&mockExchanger{}, newMockStateStore(), mockGenerator{pkceErr: errBackendDown})

		_, err := svc.Handle(
			context.Background(),
			Command{DeviceID: "device-1", DeviceType: session.DeviceWeb},
		)

		if !errors.Is(err, errBackendDown) {
			t.Fatalf("error = %v, want %v", err, errBackendDown)
		}
	})
}

func TestService_Handle_PropagatesStateStoreFailure(t *testing.T) {

	stateStore := newMockStateStore()

	stateStore.storeErr = errBackendDown

	svc := newService(&mockExchanger{}, stateStore, mockGenerator{})

	_, err := svc.Handle(
		context.Background(),
		Command{DeviceID: "device-1", DeviceType: session.DeviceWeb},
	)

	if !errors.Is(err, errBackendDown) {
		t.Fatalf("error = %v, want %v", err, errBackendDown)
	}
}
