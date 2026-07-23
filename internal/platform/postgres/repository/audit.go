package repository

import (
	"context"
	"encoding/json"

	"github.com/papanazz/auth-service-v2/internal/domain/audit"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

type AuditRepository struct {
	query *sqlc.Queries
}

func NewAuditRepository(
	query *sqlc.Queries,
) *AuditRepository {

	return &AuditRepository{
		query: query,
	}

}

func (r *AuditRepository) Record(
	ctx context.Context,
	event audit.Event,
) error {

	metadata, err :=
		json.Marshal(
			event.Metadata,
		)

	if err != nil {
		return err
	}

	_, err =
		r.query.CreateAuditLog(
			ctx,
			sqlc.CreateAuditLogParams{

				ID: event.ID,

				EventType: event.Type,

				UserID: event.UserID,

				Email: event.Email,

				IpAddress: event.IpAddress,

				UserAgent: event.UserAgent,

				Success: event.Success,

				FailureReason: event.Reason,

				Metadata: metadata,
			},
		)

	return err
}
