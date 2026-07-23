package audit

import (
	"context"
)

type Repository interface {
	Record(
		ctx context.Context,
		event Event,
	) error
}
