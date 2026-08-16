package oauth

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Repository persists Links. FindByProviderID returning "not found" is
// not itself a rejection — the caller (oauthcallback) still has to
// resolve whether this is a brand-new account or an email collision;
// see docs/adr/0001-oauth-client-and-account-linking.md.
type Repository interface {
	FindByProviderID(
		ctx context.Context,
		provider Provider,
		providerUserID string,
	) (
		*Link,
		error,
	)

	Create(
		ctx context.Context,
		link Link,
	) error

	WithTx(
		tx pgx.Tx,
	) Repository
}
