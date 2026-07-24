package refresh_token

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func timeToPgTimestamp(
	t time.Time,
) pgtype.Timestamptz {

	return pgtype.Timestamptz{
		Time:  t,
		Valid: true,
	}
}
