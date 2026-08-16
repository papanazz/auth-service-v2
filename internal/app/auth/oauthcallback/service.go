package oauthcallback

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/auth/sessionissuer"
	"github.com/papanazz/auth-service-v2/internal/app/transaction"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	domainEmail "github.com/papanazz/auth-service-v2/internal/domain/email"
	"github.com/papanazz/auth-service-v2/internal/domain/logging"
	"github.com/papanazz/auth-service-v2/internal/domain/oauth"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

type Command struct {
	Code string

	State string

	IPAddress string

	UserAgent string
}

// Result deliberately has the same shape as login.Result — from the
// client's point of view, finishing an OAuth round trip and finishing a
// password login both end in "here is your session," and there is no
// reason for the response contract to say otherwise.
type Result struct {
	AccessToken string `json:"access_token"`

	RefreshToken string `json:"refresh_token"`

	ExpiresIn int64 `json:"expires_in"`
}

type Service struct {
	exchanger oauth.Exchanger

	stateStore oauth.StateStore

	identities oauth.Repository

	users user.Repository

	issuer *sessionissuer.Issuer

	transaction transaction.Manager

	verificationTokens verification.Repository

	verificationCache verification.Cache

	verificationGenerator verification.Generator

	verificationHasher verification.Hasher

	emailPublisher domainEmail.Publisher

	audit audit.Publisher

	logger logging.Logger

	policy SecurityPolicy
}

func NewService(
	exchanger oauth.Exchanger,
	stateStore oauth.StateStore,
	identities oauth.Repository,
	users user.Repository,
	issuer *sessionissuer.Issuer,
	transaction transaction.Manager,
	verificationTokens verification.Repository,
	verificationCache verification.Cache,
	verificationGenerator verification.Generator,
	verificationHasher verification.Hasher,
	emailPublisher domainEmail.Publisher,
	audit audit.Publisher,
	logger logging.Logger,
	policy SecurityPolicy,
) *Service {

	return &Service{

		exchanger: exchanger,

		stateStore: stateStore,

		identities: identities,

		users: users,

		issuer: issuer,

		transaction: transaction,

		verificationTokens: verificationTokens,

		verificationCache: verificationCache,

		verificationGenerator: verificationGenerator,

		verificationHasher: verificationHasher,

		emailPublisher: emailPublisher,

		audit: audit,

		logger: logger,

		policy: policy,
	}
}

func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

	//
	// 1. Validate input and consume the state record
	//
	// found=false covers an unknown, expired, or already-consumed state
	// alike (oauth.StateStore's own contract) — all three get the same
	// ErrInvalidOAuthState, never a distinguishing message.
	//

	if err := Validate(cmd.Code, cmd.State); err != nil {

		return nil, err
	}

	payload, found, err :=
		s.stateStore.Consume(
			ctx,
			cmd.State,
		)

	if err != nil {
		return nil, err
	}

	if !found {

		return nil,
			errs.ErrInvalidOAuthState
	}

	//
	// 2. Redeem the authorization code
	//

	identity, err :=
		s.exchanger.Exchange(
			ctx,
			cmd.Code,
			payload.CodeVerifier,
		)

	if err != nil {
		return nil, err
	}

	//
	// 3. Resolve the identity against an existing link
	//

	link, err :=
		s.identities.FindByProviderID(
			ctx,
			identity.Provider,
			identity.ProviderUserID,
		)

	switch {

	case err == nil:

		// Case 1: a returning user — this identity is already linked.
		return s.loginLinkedAccount(ctx, cmd, payload, link.UserID)

	case errors.Is(err, errs.ErrOAuthIdentityNotFound):

		// continue below

	default:

		return nil, err
	}

	//
	// 4. No link yet — resolve by email
	//

	account, err :=
		s.users.FindByEmail(
			ctx,
			identity.Email,
		)

	switch {

	case errors.Is(err, errs.ErrUserNotFound):

		// Case 2: brand-new account.
		return s.registerAndLink(ctx, cmd, payload, identity)

	case err == nil:

		// Case 3: an account already owns this email. Both sides must
		// already be verified — the provider's own assertion and this
		// account's own verification — before auto-linking; see
		// docs/adr/0001-oauth-client-and-account-linking.md for why one
		// without the other is a real vulnerability, not just caution.
		if identity.EmailVerified && account.EmailVerifiedAt != nil {

			return s.linkAndLogin(ctx, cmd, payload, identity, account)
		}

		return nil,
			errs.ErrUserAlreadyExists

	default:

		return nil, err
	}
}

// loginLinkedAccount handles case 1: the identity is already linked to
// an account.
func (s *Service) loginLinkedAccount(
	ctx context.Context,
	cmd Command,
	payload oauth.StatePayload,
	userID uuid.UUID,
) (*Result, error) {

	account, err :=
		s.users.FindByID(
			ctx,
			userID,
		)

	if err != nil {
		return nil, err
	}

	// Mirrors login's own status gate (docs/login.md) — same reasoning:
	// only checked once the caller has proven who they are, which here
	// is the provider round trip that already happened.
	if !account.CanLogin(time.Now()) {

		if err :=
			s.audit.Publish(
				ctx,
				loginFailedEvent(
					&account.ID,
					account.Email,
					cmd.IPAddress,
					cmd.UserAgent,
					errs.ErrAccountLocked.Message,
				),
			); err != nil {

			s.logger.Error(ctx, "[OAuthCallback] audit publish failed", err, map[string]any{
				"user_id": account.ID,
			})
		}

		return nil,
			errs.ErrAccountLocked
	}

	return s.issueSession(ctx, cmd, payload, account)
}

// registerAndLink handles case 2: no user owns this email yet.
func (s *Service) registerAndLink(
	ctx context.Context,
	cmd Command,
	payload oauth.StatePayload,
	identity oauth.Identity,
) (*Result, error) {

	now := time.Now().UTC()

	account := user.NewOAuth(identity.Email)

	// A password-registered account starts PENDING and is activated
	// immediately anyway (docs/register.md) since login doesn't gate on
	// verification; an OAuth-registered account has even less reason to
	// sit PENDING.
	account.Status = user.StatusActive

	issueVerification := !identity.EmailVerified

	var rawToken string

	var verificationToken verification.Token

	var verificationTokenExpiresAt time.Time

	if identity.EmailVerified {

		account.EmailVerifiedAt = &now

	} else {

		// The provider didn't assert this email as verified — fall back
		// to the same email-verification flow register uses, rather
		// than trusting it. Deliberately duplicated here instead of
		// shared with register.Service: the two call sites diverge
		// enough (this one is conditional, embedded in a larger
		// transaction) that extracting a shared component would be
		// premature for a single reuse.
		var err error

		rawToken, err = s.verificationGenerator.Generate()

		if err != nil {
			return nil, err
		}

		verificationTokenExpiresAt =
			now.Add(s.policy.EmailVerificationTokenTTL)

		verificationToken =
			verification.Token{

				ID: uuid.New(),

				UserID: account.ID,

				Hash: s.verificationHasher.Hash(rawToken),

				ExpiresAt: verificationTokenExpiresAt,
			}
	}

	link :=
		oauth.Link{

			ID: uuid.New(),

			UserID: account.ID,

			Provider: identity.Provider,

			ProviderUserID: identity.ProviderUserID,

			Email: identity.Email,

			CreatedAt: now,
		}

	err :=
		s.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				if err := s.users.WithTx(tx).Create(ctx, account); err != nil {
					return err
				}

				if err := s.identities.WithTx(tx).Create(ctx, link); err != nil {
					return err
				}

				if issueVerification {

					return s.verificationTokens.WithTx(tx).Create(
						ctx,
						verificationToken,
					)
				}

				return nil
			},
		)

	if err != nil {
		return nil, err
	}

	//
	// Publish audit event and, if needed, the verification email — both
	// best-effort and after commit, the same stance register.Service
	// takes for its own equivalents.
	//

	if err :=
		s.audit.Publish(
			ctx,
			registeredEvent(
				account.ID,
				account.Email,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[OAuthCallback] audit publish failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	if issueVerification {

		if err :=
			s.verificationCache.StoreRawToken(
				ctx,
				verificationToken.ID,
				rawToken,
				s.policy.EmailVerificationTokenTTL,
			); err != nil {

			s.logger.Error(ctx, "[OAuthCallback] verification token cache store failed", err, map[string]any{
				"user_id": account.ID,
			})
		}

		if err :=
			s.emailPublisher.PublishVerificationEmail(
				ctx,
				domainEmail.VerificationEmail{

					To: account.Email,

					Token: rawToken,

					ExpiresAt: verificationTokenExpiresAt,
				},
			); err != nil {

			s.logger.Error(ctx, "[OAuthCallback] verification email publish failed", err, map[string]any{
				"user_id": account.ID,
			})
		}
	}

	return s.issueSession(ctx, cmd, payload, &account)
}

// linkAndLogin handles case 3a: an existing, verified account matches
// the provider's verified email — auto-link, then log in.
func (s *Service) linkAndLogin(
	ctx context.Context,
	cmd Command,
	payload oauth.StatePayload,
	identity oauth.Identity,
	account *user.User,
) (*Result, error) {

	link :=
		oauth.Link{

			ID: uuid.New(),

			UserID: account.ID,

			Provider: identity.Provider,

			ProviderUserID: identity.ProviderUserID,

			Email: identity.Email,

			CreatedAt: time.Now().UTC(),
		}

	err :=
		s.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				return s.identities.WithTx(tx).Create(ctx, link)
			},
		)

	if err != nil {
		return nil, err
	}

	if err :=
		s.audit.Publish(
			ctx,
			oauthAccountLinkedEvent(
				account.ID,
				account.Email,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[OAuthCallback] audit publish failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	if !account.CanLogin(time.Now()) {

		if err :=
			s.audit.Publish(
				ctx,
				loginFailedEvent(
					&account.ID,
					account.Email,
					cmd.IPAddress,
					cmd.UserAgent,
					errs.ErrAccountLocked.Message,
				),
			); err != nil {

			s.logger.Error(ctx, "[OAuthCallback] audit publish failed", err, map[string]any{
				"user_id": account.ID,
			})
		}

		return nil,
			errs.ErrAccountLocked
	}

	return s.issueSession(ctx, cmd, payload, account)
}

// issueSession mints the session/refresh/access token triple via the
// shared sessionissuer.Issuer and publishes the closing audit event —
// the tail end common to all three cases once an account has been
// resolved.
func (s *Service) issueSession(
	ctx context.Context,
	cmd Command,
	payload oauth.StatePayload,
	account *user.User,
) (*Result, error) {

	// device_id/name/type never traveled on Command — they came from
	// the client that started the flow, carried across the redirect
	// inside the state payload Handle already consumed (Google's own
	// redirect only carries code and state; see oauth.StatePayload's
	// doc comment).
	issued, err :=
		s.issuer.IssueForDevice(
			ctx,
			account.ID,
			payload.DeviceID,
			payload.DeviceName,
			payload.DeviceType,
			cmd.IPAddress,
			cmd.UserAgent,
		)

	if err != nil {

		if errors.Is(err, errs.ErrDeviceSessionActive) {

			if auditErr :=
				s.audit.Publish(
					ctx,
					loginFailedEvent(
						&account.ID,
						account.Email,
						cmd.IPAddress,
						cmd.UserAgent,
						errs.ErrDeviceSessionActive.Message,
					),
				); auditErr != nil {

				s.logger.Error(ctx, "[OAuthCallback] audit publish failed", auditErr, map[string]any{
					"user_id": account.ID,
				})
			}
		}

		return nil, err
	}

	if err :=
		s.audit.Publish(
			ctx,
			loginSuccessEvent(
				account.ID,
				issued.SessionID,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[OAuthCallback] audit publish failed", err, map[string]any{
			"user_id": account.ID,

			"session_id": issued.SessionID,
		})
	}

	if err :=
		s.users.UpdateLastLoginAt(
			ctx,
			account.ID,
		); err != nil {

		s.logger.Error(ctx, "[OAuthCallback] update last login at failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	return &Result{

		AccessToken: issued.AccessToken,

		RefreshToken: issued.RefreshToken,

		ExpiresIn: issued.ExpiresIn,
	}, nil
}
