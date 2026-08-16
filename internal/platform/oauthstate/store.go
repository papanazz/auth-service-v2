package oauthstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	domain "github.com/papanazz/auth-service-v2/internal/domain/oauth"
)

var _ domain.StateStore = (*Store)(nil)

type Store struct {
	client *redis.Client
}

func NewStore(
	client *redis.Client,
) *Store {

	return &Store{
		client: client,
	}
}

func (s *Store) Store(
	ctx context.Context,
	state string,
	payload domain.StatePayload,
	ttl time.Duration,
) error {

	data, err := json.Marshal(payload)

	if err != nil {
		return fmt.Errorf("marshal oauth state payload: %w", err)
	}

	if err := s.client.Set(
		ctx,
		key(state),
		data,
		ttl,
	).Err(); err != nil {

		return fmt.Errorf("store oauth state: %w", err)
	}

	return nil
}

// Consume is a single Redis GETDEL — atomic retrieve-and-delete, so a
// state value can never be presented twice successfully even under
// concurrent callback requests racing on the identical value.
func (s *Store) Consume(
	ctx context.Context,
	state string,
) (
	domain.StatePayload,
	bool,
	error,
) {

	result, err := s.client.GetDel(ctx, key(state)).Result()

	if err != nil {

		if errors.Is(err, redis.Nil) {
			return domain.StatePayload{}, false, nil
		}

		return domain.StatePayload{}, false, fmt.Errorf("consume oauth state: %w", err)
	}

	var payload domain.StatePayload

	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		return domain.StatePayload{}, false, fmt.Errorf("unmarshal oauth state payload: %w", err)
	}

	return payload, true, nil
}

// key is prefixed so a state value can never collide with an unrelated
// key pattern in this Redis instance (e.g. authattempt's or
// idempotency's — see their own key.go/store.go for the same reasoning).
func key(
	state string,
) string {

	return "oauth:state:" + state
}
