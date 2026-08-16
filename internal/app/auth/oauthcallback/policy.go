package oauthcallback

import "time"

// EmailVerificationTokenTTL is only consulted for case 2, auto-register
// with an unverified provider email (docs/adr/0001-oauth-client-and-account-linking.md)
// — the same value register.SecurityPolicy carries, configured
// separately here rather than shared, since the two use cases have no
// other reason to depend on each other's policy shape.
type SecurityPolicy struct {
	EmailVerificationTokenTTL time.Duration
}
