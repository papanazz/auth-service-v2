package session

import (
	"context"
)

type Repository interface {
	Create(ctx context.Context, session Session) error
	//Revoke(ctx context.Context,id uuid.UUID) error
}
