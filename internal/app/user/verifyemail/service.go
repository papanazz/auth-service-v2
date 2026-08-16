package verifyemail

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/papanazz/auth-service-v2/internal/app/transaction"
	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/domain/logging"
	"github.com/papanazz/auth-service-v2/internal/domain/user"
	"github.com/papanazz/auth-service-v2/internal/domain/verification"
	"github.com/papanazz/auth-service-v2/internal/platform/errs"
)

// errRaceLost is returned from inside the transaction when Consume loses
// its compare-and-swap — another concurrent verify call for the same
// token won it. Unlike refresh's replay handling, this is not a security
// signal: two callers racing to confirm the identical token both want
// the same outcome (a double-click, two open tabs, a client retry), so
// the loser is still a success, just resolved by re-reading what the
// winner already committed instead of writing anything itself.
var errRaceLost = errors.New("verification race lost")

type Command struct {
	Token string

	IPAddress string

	UserAgent string
}

type Result struct {
	Email string `json:"email"`

	VerifiedAt time.Time `json:"verified_at"`
}

type Service struct {
	transaction transaction.Manager

	tokens verification.Repository

	users user.Repository

	hasher verification.Hasher

	audit audit.Publisher

	logger logging.Logger
}

func NewService(
	transaction transaction.Manager,
	tokens verification.Repository,
	users user.Repository,
	hasher verification.Hasher,
	audit audit.Publisher,
	logger logging.Logger,
) *Service {

	return &Service{
		transaction: transaction,

		tokens: tokens,

		users: users,

		hasher: hasher,

		audit: audit,

		logger: logger,
	}
}

func (s *Service) Handle(
	ctx context.Context,
	cmd Command,
) (*Result, error) {

	//
	// 1. Locate the presented token
	//

	hash := s.hasher.Hash(cmd.Token)

	token, err :=
		s.tokens.FindByHash(
			ctx,
			hash,
		)

	if err != nil {

		if errors.Is(err, errs.ErrVerificationTokenNotFound) {

			return nil,
				errs.ErrInvalidVerificationToken
		}

		return nil, err
	}

	//
	// 2. Reject an expired, unconsumed token
	//
	// A token consumed once but now past its own ExpiresAt is not
	// rejected here — see step 3: a previously successful verification
	// must stay confirmable (idempotent), independent of the token's
	// clock.
	//

	if !token.Consumed() && token.Expired(time.Now()) {

		return nil,
			errs.ErrInvalidVerificationToken
	}

	//
	// 3. Already consumed — idempotent replay, not an error
	//
	// A second click on the same link (or a client retry) must not
	// fail: the state the caller wants ("my email is verified") is
	// already true.
	//

	if token.Consumed() {

		account, err := s.users.FindByID(ctx, token.UserID)

		if err != nil {
			return nil, err
		}

		return &Result{

			Email: account.Email,

			VerifiedAt: *account.EmailVerifiedAt,
		}, nil
	}

	//
	// 4. Verify: consume the token and mark the account verified,
	// atomically
	//

	account, err := s.users.FindByID(ctx, token.UserID)

	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	account.VerifyEmail(now)

	err =
		s.transaction.WithinTransaction(
			ctx,
			func(tx pgx.Tx) error {

				consumed, err :=
					s.tokens.WithTx(tx).Consume(
						ctx,
						token.ID,
					)

				if err != nil {
					return err
				}

				if !consumed {
					return errRaceLost
				}

				return s.users.WithTx(tx).MarkEmailVerified(
					ctx,
					account.ID,
					*account.EmailVerifiedAt,
					account.Status,
				)
			},
		)

	if err != nil {

		if errors.Is(err, errRaceLost) {

			// The winner already committed; re-read what they wrote
			// rather than erroring out the loser.
			winner, findErr := s.users.FindByID(ctx, token.UserID)

			if findErr != nil {
				return nil, findErr
			}

			return &Result{

				Email: winner.Email,

				VerifiedAt: *winner.EmailVerifiedAt,
			}, nil
		}

		return nil, err
	}

	//
	// 5. Publish audit event
	//

	if err :=
		s.audit.Publish(
			ctx,
			emailVerifiedEvent(
				account.ID,
				account.Email,
				cmd.IPAddress,
				cmd.UserAgent,
			),
		); err != nil {

		s.logger.Error(ctx, "[VerifyEmail] audit publish failed", err, map[string]any{
			"user_id": account.ID,
		})
	}

	return &Result{

		Email: account.Email,

		VerifiedAt: *account.EmailVerifiedAt,
	}, nil
}
