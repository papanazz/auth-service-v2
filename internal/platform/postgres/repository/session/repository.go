package session

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	domain "github.com/papanazz/auth-service-v2/internal/domain/session"

	"github.com/papanazz/auth-service-v2/internal/platform/errs"

	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

var _ domain.Repository = (*SessionRepository)(nil)

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
	input domain.Session,
) error {

	_, err :=
		r.query.CreateSession(
			ctx,
			mapCreateParams(input),
		)

	return err
}

func (r *SessionRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (
	*domain.Session,
	error,
) {

	row, err :=
		r.query.GetSessionByID(
			ctx,
			id,
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrSessionNotFound
		}

		return nil, err
	}

	return mapSession(row), nil
}

func (r *SessionRepository) FindActiveByID(
	ctx context.Context,
	id uuid.UUID,
) (
	*domain.Session,
	error,
) {

	row, err :=
		r.query.GetActiveSessionByID(
			ctx,
			id,
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrSessionNotFound
		}

		return nil, err
	}

	return mapSession(row), nil
}

func (r *SessionRepository) FindActiveByUserAndDevice(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) (
	*domain.Session,
	error,
) {

	row, err :=
		r.query.GetActiveSessionByUserAndDevice(
			ctx,
			sqlc.GetActiveSessionByUserAndDeviceParams{

				UserID: userID,

				DeviceID: deviceID,
			},
		)

	if err != nil {

		if errors.Is(
			err,
			sql.ErrNoRows,
		) {

			return nil,
				errs.ErrSessionNotFound
		}

		return nil, err
	}

	return mapSession(row), nil
}

func (r *SessionRepository) LockDeviceSlot(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) error {

	return r.query.LockDeviceSessionSlot(
		ctx,
		userID.String()+":"+deviceID,
	)
}

func (r *SessionRepository) Revoke(
	ctx context.Context,
	id uuid.UUID,
	reason domain.RevokeReason,
) error {

	reasonValue := string(reason)

	return r.query.RevokeSession(
		ctx,
		sqlc.RevokeSessionParams{

			ID: id,

			RevokedReason: &reasonValue,
		},
	)
}

func (r *SessionRepository) UpdateLastUsedAt(
	ctx context.Context,
	id uuid.UUID,
) error {

	return r.query.UpdateSessionLastUsedAt(
		ctx,
		id,
	)
}

func (r *SessionRepository) UpdateLastRefreshedAt(
	ctx context.Context,
	id uuid.UUID,
) error {

	return r.query.UpdateSessionLastRefreshedAt(
		ctx,
		id,
	)
}

func (r *SessionRepository) WithTx(
	tx sqlc.DBTX,
) domain.Repository {

	return &SessionRepository{

		query: sqlc.New(tx),
	}
}
