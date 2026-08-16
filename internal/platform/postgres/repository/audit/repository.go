package audit

import (
	"context"
	"fmt"

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

	if err != nil {
		return fmt.Errorf("publish authentication event: %w", err)
	}

	return nil
}
