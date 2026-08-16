package oauth

import "context"

// Exchanger is the provider-agnostic seam over a specific OAuth
// provider's authorization-code flow — the app layer never sees a
// Google-specific (or any other provider's) shape, the same separation
// domain/password.Hasher already gives Argon2id.
type Exchanger interface {
	// AuthCodeURL builds the URL to redirect the user to. codeChallenge
	// is the PKCE S256 challenge derived from a verifier the caller
	// generated and will present again in Exchange.
	AuthCodeURL(
		state string,
		codeChallenge string,
	) string

	// Exchange redeems an authorization code for the identity of
	// whoever just authenticated. codeVerifier must be the exact PKCE
	// verifier the challenge passed to AuthCodeURL was derived from.
	Exchange(
		ctx context.Context,
		code string,
		codeVerifier string,
	) (Identity, error)
}
