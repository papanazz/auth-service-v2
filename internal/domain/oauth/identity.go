package oauth

// Identity is what a successful code exchange yields — a provider's
// account of who just authenticated. It is never persisted directly:
// the account-linking policy (docs/adr/0001-oauth-client-and-account-linking.md)
// decides what to do with it, and Link is the record of that decision.
type Identity struct {
	Provider Provider

	// ProviderUserID is the provider's own stable identifier for the
	// account (Google's "sub" claim) — never the email, which a user
	// can change on the provider's side without changing who they are.
	ProviderUserID string

	Email string

	// EmailVerified is the provider's own assertion that Email belongs
	// to whoever just authenticated — not this service's opinion, and
	// not to be confused with the target account's own
	// user.EmailVerifiedAt. The account-linking policy requires both to
	// be true before auto-linking; see the ADR referenced above for why
	// one without the other isn't enough.
	EmailVerified bool

	Name string
}
