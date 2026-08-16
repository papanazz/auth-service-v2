package oauth

// Provider identifies which third-party identity provider an Identity
// or Link came from. Google is the only one wired up today
// (docs/oauth.md) — adding a second provider means a new constant here
// and a new Exchanger implementation, not a change to this type or to
// any of the account-linking logic that keys off it.
type Provider string

const (
	ProviderGoogle Provider = "GOOGLE"
)
