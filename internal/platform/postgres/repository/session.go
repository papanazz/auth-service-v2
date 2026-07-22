package repository

import (
	"context"

	"github.com/papanazz/auth-service-v2/internal/domain/session"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

type SessionRepository struct {
	query *sqlc.Queries
}

func NewSessionRepository(
	query *sqlc.Queries,
) *SessionRepository {

	return &SessionRepository{
		query: query,
	}
}

func (r *SessionRepository) Create(
	ctx context.Context,
	s session.Session,
) error {

	_, err :=
		r.query.CreateSession(
			ctx,
			sqlc.CreateSessionParams{

				ID: s.ID,

				UserID: s.UserID,

				DeviceID: s.DeviceID,

				DeviceName: s.DeviceName,

				DeviceType: sqlc.DeviceType(s.DeviceType),

				UserAgent: s.UserAgent,

				IpAddress: s.IpAddress,
			},
		)

	return err
}
