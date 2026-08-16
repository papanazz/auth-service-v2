package logging

import "context"

// Logger is the minimal logging capability a use case needs: recording
// a best-effort side effect it has already decided not to fail the
// request over (an audit publish, a cache store, an email send) — never
// business-outcome logging, which stays at the transport boundary (see
// docs/logging.md). One method, deliberately: a use case has no reason
// to log at any other severity, since anything worth failing the
// request over is returned as an error instead, not logged here.
//
// Satisfied transparently by *platform/logger.Logger — logger.Metadata
// is a type alias for map[string]any specifically so no adapter is
// needed to bridge platform's concrete type into this interface.
type Logger interface {
	Error(
		ctx context.Context,
		message string,
		err error,
		metadata map[string]any,
	)
}
