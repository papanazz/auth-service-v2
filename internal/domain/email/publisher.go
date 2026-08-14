package email

import (
	"context"
	"time"
)

// VerificationEmail is the content a Publisher needs to deliver an
// email-verification link — everything except how delivery actually
// happens.
type VerificationEmail struct {
	To string

	// Token is the raw, unhashed verification token. It exists only
	// here, in the moment of publishing, and in Cache's short-lived
	// Redis copy — never in Postgres.
	Token string

	ExpiresAt time.Time
}

// Publisher hands a verification email off for delivery.
//
// No implementation in this codebase actually sends email yet — see
// platform/email.LogPublisher, which logs what would have been sent.
// The interface exists so that swapping in a real provider later (SES,
// Postmark, ...) touches one adapter, not every caller.
type Publisher interface {
	PublishVerificationEmail(
		ctx context.Context,
		email VerificationEmail,
	) error
}
