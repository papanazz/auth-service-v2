package refresh_token

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	domain "github.com/papanazz/auth-service-v2/internal/domain/refresh_token"
	"github.com/papanazz/auth-service-v2/internal/platform/postgres/sqlc"
)

func mapCreateParams(
	input domain.Token,
) sqlc.CreateRefreshTokenParams {

	return sqlc.CreateRefreshTokenParams{

		ID: input.ID,

		SessionID: input.SessionID,

		FamilyID: input.FamilyID,

		ParentTokenID: input.ParentTokenID,

		TokenHash: input.Hash,

		ExpiresAt: toTimestamp(
			input.ExpiresAt,
		),
	}

}

func mapToken(
	row sqlc.RefreshToken,
) *domain.Token {

	var revokeReason *domain.RevokeReason

	if row.RevokedReason.Valid {

		value :=
			domain.RevokeReason(
				row.RevokedReason.RefreshTokenRevokeReason,
			)

		revokeReason =
			&value
	}

	return &domain.Token{

		ID: row.ID,

		SessionID: row.SessionID,

		FamilyID: row.FamilyID,

		ParentTokenID: row.ParentTokenID,

		Hash: row.TokenHash,

		ExpiresAt: row.ExpiresAt.Time,

		ConsumedAt: fromTimestamp(
			row.ConsumedAt,
		),

		RevokedAt: fromTimestamp(
			row.RevokedAt,
		),

		RevokedReason: revokeReason,

		CreatedAt: row.CreatedAt.Time,
	}

}

func toTimestamp(
	value time.Time,
) pgtype.Timestamptz {

	return pgtype.Timestamptz{

		Time: value,

		Valid: true,
	}
}

func fromTimestamp(
	value pgtype.Timestamptz,
) *time.Time {

	if !value.Valid {
		return nil
	}

	return &value.Time
}

func timeToPgTimestamp(
	t time.Time,
) pgtype.Timestamptz {

	return pgtype.Timestamptz{
		Time:  t,
		Valid: true,
	}
}
