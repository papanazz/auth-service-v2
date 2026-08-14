# Logging

Structured JSON logging via `internal/platform/logger` (zap underneath).
Every log line carries `log_id`/`trace_id`/`request_id` automatically
(`logger.GetTraceID` reads the active OpenTelemetry span, tying a log
line to a Jaeger trace for free — see `docs/tracing.md`).

Like `docs/metrics.md`/`docs/tracing.md`/`docs/health.md`, this is a
cross-cutting doc, not a per-endpoint one.

## Logging

### Per-request line

`internal/transport/http/middleware/logger.go` logs one `http_request`
INFO line per request — `method`, `path`, `status`, `duration`,
`remote_ip` — for every route except `/metrics`, `/health`, and
`/ready`. The first two are scraped/polled far too often to be worth a
line each; `/ready` joined them for the same reason once
`docker-compose.yml` started polling it every 5s (`docs/health.md`) —
included from the start would have meant a steady drip of log lines
carrying no information beyond "the healthcheck ran again."

### Error logging — `response.LogAndWriteError`

Every handler's service-call failure goes through one shared function,
`internal/transport/http/response.LogAndWriteError`, instead of each
handler calling `h.logger.Error` directly and then `response.WriteError`
separately (which is what all six did before this pass — see Decisions
for why that shape was itself the problem). It:

1. Resolves the HTTP status via `StatusForError` — the same mapping
   `WriteError` uses, so the two can never disagree.
2. Adds `error_code` to the log metadata when `err` is an `*errs.Error`
   (e.g. `AUTH_REFRESH_TOKEN_REPLAY`, `DEVICE_SESSION_ALREADY_ACTIVE`) —
   the machine-readable code, not just the human-readable message.
3. Logs at **Warn** for 4xx, **Error** for 5xx (see Decisions).
4. Writes the error response via the existing `WriteError`.

Handlers pass whatever safe, non-secret context is available at that
point — see the table below.

### Decode-failure logging

A malformed request body is always a 400, so it's always logged at
`Warn`, directly (`h.logger.Warn(ctx, "[X] malformed request body",
logger.Metadata{"error": err.Error()})`), by every one of the six
handlers uniformly — before this pass, only register and login logged
anything here at all, and both logged it at `Error`.

### What each endpoint's error log carries

| Endpoint | Safe metadata logged | Never logged |
|---|---|---|
| Register | `email` (masked), `user_agent` | password |
| Login | `email` (masked), `device_id`, `device_type`, `user_agent` | password |
| Refresh | `user_agent` | the refresh token |
| Logout | `user_agent` | the refresh token |
| Verify Email | `user_agent` | the verification token |
| Resend Verification | `email` (masked), `user_agent` | — (no secret in the request) |

Refresh, logout, and verify-email have no email/user_id available at the
handler layer on failure — only the service, past the point of failure,
ever resolves one from the token, and returning it upward just to log it
would mean threading business data back out through an error return
purely for logging, which isn't worth the coupling. The trace span
already carries `user.id`/`session.id` once a request gets far enough to
audit-publish (`docs/tracing.md`) — that's the correlation path for
those three today, not the log line.

### `logger.MaskEmail`

Keeps the first one or two characters of the local part and the whole
domain, replaces the rest with `***` — `bayu.aditya@example.com` becomes
`ba***@example.com`. Enough to eyeball- or grep-match a specific known
account (or spot a wave of signups from one domain) without putting a
full address in plaintext into a log stream that, unlike the Postgres
column it's also stored in, may ship to a third-party aggregator with
different retention and access rules.

## Decisions

- **Logging and responding are one call, not two.** Every handler used
  to call `h.logger.Error(...)` and `response.WriteError(...)`
  separately — two calls with no shared source of truth, which is
  exactly how they drifted: every error, a `401` from a wrong password
  and a `500` from a dead connection alike, was logged at the same
  `Error` level, because nothing tied the log call's severity to the
  status the response actually carried. `LogAndWriteError` makes that
  drift structurally impossible — one function resolves the status once
  and both the severity and the response are derived from it.

- **Warn for 4xx, Error for 5xx** — not any finer-grained a split, and
  not configurable per error code. A 4xx is definitionally something the
  *client* caused: a wrong password, a rate limit, a stale token. Those
  are expected in volume and are exactly what an attacker's probing
  looks like too — logging them at Error would mean a real Postgres or
  Redis outage (also logged at Error, now) is drowned in the same
  stream as routine, high-volume client noise, defeating the entire
  point of a severity level. Verified live: killing Redis mid-request
  produced an `ERROR` line with the real driver message ("dial tcp:
  lookup redis... no such host"), sitting cleanly apart from `WARN`
  lines for a duplicate registration, a wrong password, and an invalid
  verification token generated in the same window.

- **The error's `Code` is added as its own field (`error_code`), not
  left to whatever `err.Error()` happens to say.** `errs.Error.Error()`
  returns only `.Message` — for `ErrDeviceSessionActive` that's "an
  active session already exists for this device", which shares almost
  no words with its code, `DEVICE_SESSION_ALREADY_ACTIVE`. Before this
  change, there was no way to build a log query or alert keyed on a
  stable error code; you'd have to match free text. `error_code` is
  exactly the same string `metrics.AuditPublisher` and
  `tracing.AuditPublisher` key their own signals on (`docs/metrics.md`,
  `docs/tracing.md`) — logs, metrics, and traces now agree on one
  vocabulary for "what happened."

- **Secrets are never logged, masked or not — only PII is masked.**
  There's a real difference between the two: a password or a raw
  refresh/verification token *is* the credential, so any fragment of it
  in a log is a live exposure (the same class of bug fixed in
  `docs/tracing.md`'s Redis `db.statement` leak). An email address is
  identifying but not something an attacker can use to authenticate —
  masking it is a privacy courtesy for a log stream with broader access
  than the database, not a security boundary. Treating both the same
  way (either logging both raw, or masking both) would either leak a
  credential or apply security-grade caution to a field that doesn't
  need it.

- **`response.LogAndWriteError` takes a narrow `levelLogger` interface
  (`Warn`/`Error` only), not the concrete `*logger.Logger`.** `*logger.Logger`
  wraps zap directly with no way to construct one backed by a test
  double, so a narrow interface — satisfied transparently by
  `*logger.Logger`, no handler call site changed — is what makes the
  severity-selection logic (Decisions above) testable without spinning
  up zap or asserting on captured stdout.

- **`/ready` was added to the per-request logging exclusion list in the
  same pass**, not filed as a separate gap. It's a direct, mechanical
  consequence of `docs/health.md` adding a Docker-polled endpoint
  without anyone updating the adjacent exclusion list — caught while
  reviewing logging end-to-end, cheap enough to fix immediately rather
  than defer.

## Capabilities

- Every error response's severity now agrees with its HTTP status —
  verified live, not just by inspection.
- Every error log carries a stable, greppable `error_code` alongside the
  human-readable message.
- Login, register, and resend-verification failures are greppable by a
  partially-masked email; no endpoint's logs ever carry a password or a
  raw token.
- `/health`, `/ready`, and `/metrics` — the three endpoints polled on a
  fixed interval by infrastructure, not requested by a real caller — are
  all excluded from the per-request log line.

## Gaps

- **Refresh, logout, and verify-email still can't be grepped by
  user/session on failure** — see the table above. Not fixed in this
  pass: the fix is threading a resolved identifier back out of the
  service layer specifically for logging, which is a real design
  question (does `Command`/`Result` grow a field only failure-path
  logging needs?) rather than a mechanical one, and out of scope for a
  logging-usage review. The trace span is the correlation path today.
- **No log line at all for a *successful* login/register/refresh** — the
  generic `http_request` INFO line is the only trace of a success in the
  log stream; the identifying detail (`user.id`, `session.id`) lives in
  the audit table and on the trace span, not in a log line a person
  tailing `docker logs` would see directly. Considered during this
  review and deliberately not added: a success-path log line for six
  endpoints is a real scope expansion (what fields, what level, is it
  worth the added log volume for something already durably recorded
  twice over) that deserves its own pass rather than being folded into
  an error-logging review.
- **`logger.MaskEmail` is a fixed scheme, not configurable.** Reasonable
  for a service this size; a compliance regime with stricter PII
  handling requirements (hash instead of partial-reveal, for instance)
  would need this to be pluggable rather than the one hardcoded shape.

## Tested Scenarios

Unit — `internal/platform/logger/mask_test.go`
(`go test ./internal/platform/logger/... -race`):

- typical, one-character, and two-character local parts are each masked
  correctly, keeping only as many characters as actually exist
- no `@`, an empty local part, and the empty string all fall back to a
  fixed `"***"` rather than ever echoing the raw input
- the full local part never survives in the output, regardless of length

Unit — `internal/transport/http/response/errors_test.go`
(`go test ./internal/transport/http/response/... -race`):

- `StatusForError` maps every defined error code to its documented
  status, and an unmapped raw error to `500`
- a 4xx (`ErrInvalidCredentials`) logs at Warn; a raw, unmapped error
  (mapping to 500) logs at Error, carrying the original error value
- `error_code` is added to the metadata map without disturbing the
  caller's own fields
- the Warn path's metadata includes `error` (the message) — Warn has no
  `err` parameter the way Error does, so this is added explicitly
- a `nil` metadata map doesn't panic

e2e — against the real docker-compose stack:

- register success → duplicate-email retry → `409`, logged at `WARN`
  with `error_code:"USER_ALREADY_EXISTS"` and a masked email
- login with the wrong password → `401`, logged at `WARN` with
  `error_code:"INVALID_CREDENTIALS"`, masked email, `device_id`,
  `device_type`, `user_agent`
- malformed JSON to `/v1/auth/refresh` → `400`, logged at `WARN` with the
  real JSON decode error
- an unknown token to `/v1/user/verify-email` → `400`, logged at `WARN`
  with `error_code:"INVALID_VERIFICATION_TOKEN"`
- `docker stop` the Redis container, then a login attempt → `500`,
  logged at **`ERROR`** with the real driver message ("dial tcp: lookup
  redis... no such host"), the masked email, and the same
  `device_id`/`device_type`/`user_agent` fields the Warn path carries —
  sitting distinctly apart, by level, from every 4xx logged in the same
  window
- confirmed zero `http_request` log lines for `path:"/ready"` despite
  Docker polling it every 5s throughout the test run

## Related Files

```
internal/platform/logger/logger.go            Logger: Info/Debug/Warn/Error/Fatal
internal/platform/logger/mask.go              MaskEmail
internal/platform/logger/context.go           log_id/trace_id/request_id correlation
internal/transport/http/response/errors.go    StatusForError, LogAndWriteError
internal/transport/http/middleware/logger.go  per-request line, exclusion list
internal/transport/http/handler/*.go          decode-failure Warn, LogAndWriteError call sites
```
