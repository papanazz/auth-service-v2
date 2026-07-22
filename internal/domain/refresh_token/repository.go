package refresh_token

import (
	"context"
)

type Repository interface {
	Create(ctx context.Context, token Token) error
	//FindByHash(ctx context.Context, hash string) (*Token, error)
	//Revoke(ctx context.Context, id uuid.UUID) error
}
