package email

import (
	"context"

	domain "github.com/papanazz/auth-service-v2/internal/domain/email"
	"github.com/papanazz/auth-service-v2/internal/platform/logger"
)

var _ domain.Publisher = (*LogPublisher)(nil)

// LogPublisher stands in for a real email provider (SES, Postmark, ...),
// which this codebase does not integrate with yet. It logs what would
// have been sent instead of sending it, so the verification flow is
// fully exercisable — register, verify, resend, and their audit trail —
// without a delivery mechanism blocking any of it. Swapping in a real
// provider later means writing one adapter against domain/email.Publisher
// and rewiring app.New; no caller changes.
type LogPublisher struct {
	logger *logger.Logger
}

func NewLogPublisher(
	log *logger.Logger,
) *LogPublisher {

	return &LogPublisher{
		logger: log,
	}
}

func (p *LogPublisher) PublishVerificationEmail(
	ctx context.Context,
	verificationEmail domain.VerificationEmail,
) error {

	p.logger.Info(
		ctx,
		"[email] verification email not sent — no provider configured",
		logger.Metadata{
			"to": verificationEmail.To,

			"token": verificationEmail.Token,

			"expires_at": verificationEmail.ExpiresAt,
		},
	)

	return nil
}
