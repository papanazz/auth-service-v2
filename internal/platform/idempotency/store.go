package idempotency

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// Record is the cached outcome of a request identified by an idempotency
// key.
//
// Status is 0 while the request is still being processed: the zero value
// distinguishes an in-flight reservation from a completed response, so a
// caller that loses the claim race can tell the two apart without a second
// field.
type Record struct {
	Status int `json:"status"`

	Body []byte `json:"body"`

	// RequestHash lets a caller detect a key reused with a different
	// request body — a client bug, not a legitimate retry.
	RequestHash string `json:"request_hash"`
}

func (r Record) InProgress() bool {
	return r.Status == 0
}

type Store struct {
	client *redis.Client

	script *redis.Script
}

func NewStore(
	client *redis.Client,
) *Store {

	return &Store{

		client: client,

		script: redis.NewScript(
			claimScript,
		),
	}
}

// TryClaim atomically reserves key for processing.
//
// claimed is true when the caller won the reservation and must go on to
// process the request and call Save (or Release on failure). When claimed
// is false, existing holds whatever is currently stored for key — either a
// completed Record or another caller's still-in-flight reservation
// (existing.InProgress()) — for the caller to act on.
func (s *Store) TryClaim(
	ctx context.Context,
	key string,
	requestHash string,
	reservationTTL time.Duration,
) (
	claimed bool,
	existing *Record,
	err error,
) {

	placeholder, err :=
		json.Marshal(
			Record{
				RequestHash: requestHash,
			},
		)

	if err != nil {
		return false, nil, err
	}

	result, err :=
		s.script.Run(
			ctx,
			s.client,
			[]string{
				key,
			},
			placeholder,
			int(
				reservationTTL.Seconds(),
			),
		).
			Text()

	if err != nil {
		return false, nil, err
	}

	if result == "" {
		return true, nil, nil
	}

	var record Record

	if err :=
		json.Unmarshal(
			[]byte(result),
			&record,
		); err != nil {

		return false, nil, err
	}

	return false, &record, nil
}

// Save stores the completed outcome for key, replacing the reservation
// placeholder so subsequent callers replay it instead of reprocessing.
func (s *Store) Save(
	ctx context.Context,
	key string,
	record Record,
	ttl time.Duration,
) error {

	data, err :=
		json.Marshal(
			record,
		)

	if err != nil {
		return err
	}

	return s.client.Set(
		ctx,
		key,
		data,
		ttl,
	).Err()
}

// Release drops a reservation without caching an outcome, so the next
// attempt — by this caller's own retry, or another waiter — starts fresh
// instead of being stuck behind a claim that will never complete.
func (s *Store) Release(
	ctx context.Context,
	key string,
) error {

	return s.client.Del(
		ctx,
		key,
	).Err()
}
