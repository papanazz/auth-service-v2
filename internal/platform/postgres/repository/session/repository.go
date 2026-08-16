package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	return nil
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

		return nil, fmt.Errorf("get session by id: %w", err)
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

		return nil, fmt.Errorf("get active session by id: %w", err)
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

		return nil, fmt.Errorf("get active session by user and device: %w", err)
	}

	return mapSession(row), nil
}

func (r *SessionRepository) LockDeviceSlot(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) error {

	err := r.query.LockDeviceSessionSlot(
		ctx,
		userID.String()+":"+deviceID,
	)

	if err != nil {
		return fmt.Errorf("lock device session slot: %w", err)
	}

	return nil
}

func (r *SessionRepository) Revoke(
	ctx context.Context,
	id uuid.UUID,
	reason domain.RevokeReason,
) error {

	reasonValue := string(reason)

	err := r.query.RevokeSession(
		ctx,
		sqlc.RevokeSessionParams{

			ID: id,

			RevokedReason: &reasonValue,
		},
	)

	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

func (r *SessionRepository) UpdateLastUsedAt(
	ctx context.Context,
	id uuid.UUID,
) error {

	err := r.query.UpdateSessionLastUsedAt(
		ctx,
		id,
	)

	if err != nil {
		return fmt.Errorf("update session last used at: %w", err)
	}

	return nil
}

func (r *SessionRepository) UpdateLastRefreshedAt(
	ctx context.Context,
	id uuid.UUID,
) error {

	err := r.query.UpdateSessionLastRefreshedAt(
		ctx,
		id,
	)

	if err != nil {
		return fmt.Errorf("update session last refreshed at: %w", err)
	}

	return nil
}

func (r *SessionRepository) WithTx(
	tx sqlc.DBTX,
) domain.Repository {

	return &SessionRepository{

		query: sqlc.New(tx),
	}
}
