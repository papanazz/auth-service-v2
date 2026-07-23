package user

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	FindByID(
		ctx context.Context,
		id uuid.UUID,
	) (
		*User,
		error,
	)

	FindByEmail(
		ctx context.Context,
		email string,
	) (
		*User,
		error,
	)

	Create(
		ctx context.Context,
		user User,
	) error
}
