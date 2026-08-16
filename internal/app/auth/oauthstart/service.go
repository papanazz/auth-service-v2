package oauthstart

import (
	"context"
	"strings"
	"time"

	"github.com/papanazz/auth-service-v2/internal/domain/oauth"
	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	DeviceID string

	DeviceName string

	DeviceType session.DeviceType
}

type Result struct {
	AuthURL string `json:"auth_url"`
}

type SecurityPolicy struct {
	StateTTL time.Duration
}

type Service struct {
	exchanger oauth.Exchanger

	stateStore oauth.StateStore

	generator oauth.Generator

	policy SecurityPolicy
}

func NewService(
	exchanger oauth.Exchanger,
	stateStore oauth.StateStore,
	generator oauth.Generator,
	policy SecurityPolicy,
) *Service {

	return &Service{

		exchanger: exchanger,

		stateStore: stateStore,

		generator: generator,

		policy: policy,
	}
}

func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

	//
	// 1. Validate input
	//
	// device_id/device_type are validated here, not deferred to the
	// callback: they travel inside the state payload untouched (Google's
	// redirect carries back only code and state, nothing else — see
	// docs/oauth.md), so a value that would fail sessionissuer.Issuer's
	// own checks later is better rejected now than after a real round
	// trip through Google.
	//

	if strings.TrimSpace(cmd.DeviceID) == "" {

		return nil, errs.ErrInvalidRequest
	}

	if !cmd.DeviceType.Valid() {

		return nil, errs.ErrInvalidRequest
	}

	//
	// 2. Generate state and PKCE
	//

	state, err := s.generator.GenerateState()

	if err != nil {
		return nil, err
	}

	verifier, challenge, err := s.generator.GeneratePKCE()

	if err != nil {
		return nil, err
	}

	//
	// 3. Store the state record
	//
	// Single-use, short-TTL — oauthcallback consumes it exactly once.
	// See oauth.StateStore's own doc comment for why an unknown, expired,
	// or already-consumed state must be indistinguishable to the caller.
	//

	if err :=
		s.stateStore.Store(
			ctx,
			state,
			oauth.StatePayload{

				CodeVerifier: verifier,

				DeviceID: cmd.DeviceID,

				DeviceName: cmd.DeviceName,

				DeviceType: cmd.DeviceType,
			},
			s.policy.StateTTL,
		); err != nil {

		return nil, err
	}

	return &Result{

		AuthURL: s.exchanger.AuthCodeURL(state, challenge),
	}, nil
}
