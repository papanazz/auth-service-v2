package audit

import (
	"context"

	domain "github.com/papanazz/auth-service-v2/internal/domain/audit"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var _ domain.Publisher = (*AuditPublisher)(nil)

type AuditPublisher struct {
	query *sqlc.Queries
}

func NewAuditPublisher(
	query *sqlc.Queries,
) *AuditPublisher {

	return &AuditPublisher{
		query: query,
	}

}

func (p *AuditPublisher) Publish(
	ctx context.Context,
	event domain.Event,
) error {

	_, err :=
		p.query.CreateAuthenticationEvent(
			ctx,
			mapCreateParams(event),
		)

	return err
}
