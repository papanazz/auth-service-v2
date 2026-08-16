package oauth

// Generator produces the two random values oauthstart needs: state (CSRF
// protection) and a PKCE code_verifier/code_challenge pair. Mirrors
// refresh_token.Generator and verification.Generator's shape — a
// platform/crypto-rand implementation behind a domain interface, so
// oauthstart's own tests can supply deterministic values instead of
// depending on real randomness.
type Generator interface {
	GenerateState() (
		string,
		error,
	)

	// GeneratePKCE returns a verifier (kept secret, stored server-side
	// via StateStore, presented again at Exchange) and its S256
	// challenge (sent to the provider up front, in AuthCodeURL).
	GeneratePKCE() (
		verifier string,
		challenge string,
		err error,
	)
}
