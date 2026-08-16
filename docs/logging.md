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

### Error wrapping through the platform layer

Every repository and platform adapter (`internal/platform/postgres/repository/*`,
`internal/platform/redis`, `internal/platform/authattempt`,
`internal/platform/idempotency`, `internal/platform/token`,
`internal/platform/password`, `internal/platform/refresh_token`,
`internal/platform/verification`) now wraps a raw, unexpected error with
one short static phrase before returning it —
`fmt.Errorf("get user by email: %w", err)`, not just `return nil, err`.
Sentinel translations (`sql.ErrNoRows` → `errs.ErrUserNotFound` and
similar) are untouched — only the *fallback* path, the one that used to
return the driver's bare error, gets a phrase. By the time an unexpected
failure reaches `response.LogAndWriteError`, the log line reads like a
breadcrumb — `"get user by email: dial tcp: connection refused"` — not
just the bottom of the stack with no indication of which call produced
it. See Decisions for the one place this is deliberately *not* done
(`TransactionManager.WithinTransaction`'s `fn(tx)` return).

### Best-effort logging — `domain/logging.Logger`

Every use case (`register`, `login`, `refresh`, `logout`, `verifyemail`,
`resendverification`) now takes a `domain/logging.Logger` — one method,
`Error(ctx, message, err, metadata)` — and calls it wherever a
best-effort side effect (an audit publish, a cache store, an email send,
a rate-limit counter update) used to discard its error with a bare
`_ = ...`. Nothing else about those call sites changed: the error still
doesn't fail the request, since none of them were ever meant to. What
changed is that failure is no longer invisible — before this, if the
Postgres audit-log write failed during an outage, nothing anywhere
recorded that fact; `metrics.AuditPublisher` and `tracing.AuditPublisher`
both fire before forwarding to the real publisher (`docs/metrics.md`,
`docs/tracing.md`), so even the metric and the trace span don't
distinguish "recorded" from merely "attempted." The log line is now the
one place that distinction survives.

`domain/logging.Logger` lives in `domain`, not `platform` — the
dependency-inversion rule in the top-level `CLAUDE.md` ("`domain` and
`app` never import `platform` ... concretely") applies to `app`-layer
use cases the same way it applies to everything else, so a use case
logging couldn't just import `platform/logger` directly. `logger.Metadata`
is a type *alias* for `map[string]any` (`internal/platform/logger/metadata.go`)
specifically so `*logger.Logger` satisfies the domain interface with no
adapter — Go's interface matching needs the exact type, and an alias
means there are not two types to bridge, only one spelled two ways.

### NotFound vs. genuine failure

Three lookups — login's `FindByEmail`, and refresh's and logout's
`FindByHash`/`FindByID` — used to treat *any* error from the repository,
not just "not found," as the business outcome ("unknown account",
"invalid token"). A real repository failure (Postgres unreachable, a
timeout) was silently folded into the same 401 a wrong password or a
stale token produces — misreporting a 500-class incident as routine
auth failure, both to the client and, before this pass, to the log
(`WARN` instead of `ERROR`, since the fold happened before severity was
even decided). Fixed by checking `errors.Is(err, <specific NotFound
sentinel>)` first — `errs.ErrUserNotFound`, `errs.ErrRefreshTokenNotFound`
(new — `refresh_token.Repository.FindByHash` had no sentinel translation
at all before this pass, see Decisions), `errs.ErrSessionNotFound` — and
only taking the enumeration-safe/idempotent branch when it matches;
anything else now propagates unchanged. `register` and `resendverification`
already did this correctly; `verifyemail` did too. Verified live: a
login attempt with Postgres stopped now returns `500` (previously would
have been `401`), logged at `ERROR` with `"get user by email: failed to
connect to ...: no such host"`.

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

- **`TransactionManager.WithinTransaction` never wraps `fn(tx)`'s
  returned error, even though it wraps its own `BeginTx`/`Commit`
  failures.** `fn` is the use case's own transactional closure — its
  error might be a raw repository failure (already wrapped there, if
  so) or a domain sentinel the use case deliberately returns from inside
  the closure (login's `errs.ErrDeviceSessionActive`, for one).
  `response.WriteError`/`StatusForError` type-assert `err.(*errs.Error)`
  directly rather than using `errors.As` — wrapping here would silently
  turn every such sentinel into an unwrapped `*fmt.wrapError`, which
  fails that assertion and falls through to a `500` no matter what the
  sentinel actually was. `WithinTransaction` has no way to tell which
  case it's looking at, so passing `fn`'s error through completely
  untouched is the only choice that can't misroute a real business
  error into a wrong status code.

- **Repository errors are wrapped with what the call was doing, not
  which repository or table it touched.** `"get user by email: %w"`,
  not `"UserRepository.FindByEmail: %w"` or `"users table: %w"` — the
  phrase is meant to read naturally next to the wrapped message in one
  log line, and the operation is more useful for that than the
  implementation detail of which Go type or SQL table was involved.

- **The NotFound-conflation bug existed in three places
  (login/refresh/logout) but not in three others (register/verifyemail/
  resendverification) that do the identical kind of lookup.** Worth
  naming plainly: this wasn't a one-off typo, it was the same mistake
  made three times and avoided three times, which is exactly the shape
  of bug a shared pattern (or a lint rule, if one existed for it) would
  have caught structurally instead of relying on each service getting
  it right independently. Flagged here rather than silently fixed,
  since the next new use case with a "does this exist" lookup is exactly
  where it could recur.

- **`errs.ErrRefreshTokenNotFound` is a new sentinel, not a reuse of
  `errs.ErrInvalidRefreshToken`.** The two mock repositories (refresh's
  and logout's) were themselves returning `ErrInvalidRefreshToken` —
  the *client-facing* error — directly from a not-found lookup, before
  this pass, which is exactly backwards: a repository has no business
  deciding what a client sees, only the service layer does. Both mocks
  were fixed alongside the new sentinel so the tests assert against the
  same contract the real `RefreshTokenRepository` now honors.

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
- A genuine repository failure can no longer be misreported as "unknown
  account" or "invalid token" — verified live against Postgres actually
  being down, not just reasoned about (see NotFound vs. genuine failure
  above).
- Unexpected errors carry a breadcrumb of which repository call produced
  them (`"get user by email: %w"`), not just the bare driver message —
  across every platform adapter, not only the ones on the hot path for
  login/register.
- Every best-effort side effect a use case swallows (audit publish,
  verification-token cache store, email publish, rate-limit counter
  update) is now logged at `Error` on failure instead of vanishing —
  ~28 call sites across all six use cases, none of which required
  changing what the use case actually does when they fail (still
  best-effort, still doesn't fail the request).

## Gaps

- **Refresh, logout, and verify-email still can't be grepped by
  user/session on failure** — see the table above. Not fixed in this
  pass: the fix is threading a resolved identifier back out of the
  service layer specifically for logging, which is a real design
  question (does `Command`/`Result` grow a field only failure-path
  logging needs?) rather than a mechanical one, and out of scope for a
  logging-usage review. The trace span is the correlation path today.
- **A failed transaction rollback is still unlogged.**
  `TransactionManager.WithinTransaction`'s deferred `tx.Rollback(...)`
  (`internal/platform/postgres/repository/transaction.go`) discards its
  own error — reasonable low-priority scope cut, since a rollback is
  only attempted when the transaction is already being abandoned (a
  `Commit` or `fn(tx)` failure that's *already* logged/propagated), and
  a rollback failing is itself usually a symptom of the same dead
  connection that caused the original failure, not new information.
  Would need the `TransactionManager` to take its own `logging.Logger`
  to fix, a different injection point than the six use cases this pass
  covers.
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

Unit — each of the six use cases' own test suite
(`go test ./internal/app/... -race`), extended in this pass:

- login: a genuine `FindByEmail` failure propagates unmasked — not
  `ErrInvalidCredentials` — and the dummy-hash verification does not run
  for it (`TestLoginService_Handle_PropagatesAGenuineLookupFailureUnmasked`);
  a swallowed `UpdateLastLoginAt` failure is now asserted present in the
  mock logger, not just tolerated
  (`TestLoginService_Handle_TolerateLastLoginAtFailure`)
- refresh and logout: a genuine `FindByHash`/`FindByID` failure
  propagates unmasked, for both repositories independently
  (`propagates a genuine token/session lookup failure unmasked`)
- register: swallowed cache-store and email-publish failures are now
  asserted present in the mock logger, not just tolerated
  (`TestRegisterService_Handle_ToleratesCacheAndEmailFailures`)

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
- `docker stop` the Postgres container, then a login attempt → `500`
  (previously would have been a misleading `401`), logged at **`ERROR`**
  with `"get user by email: failed to connect to \`user=postgres
  database=auth_system\`: hostname resolving error: lookup postgres on
  127.0.0.11:53: no such host"` — the wrapping phrase and the underlying
  driver error in one line — sitting distinctly apart, by level, from a
  `WARN`-logged wrong-password attempt captured in the same window with
  the identical `device_id`/`device_type`/`user_agent`/masked-email
  fields
- confirmed zero `http_request` log lines for `path:"/ready"` despite
  Docker polling it every 5s throughout the test run

## Related Files

```
internal/platform/logger/logger.go            Logger: Info/Debug/Warn/Error/Fatal
internal/platform/logger/mask.go              MaskEmail
internal/platform/logger/metadata.go          Metadata (alias for map[string]any)
internal/platform/logger/context.go           log_id/trace_id/request_id correlation
internal/domain/logging/logger.go             Logger — best-effort logging interface
internal/transport/http/response/errors.go    StatusForError, LogAndWriteError
internal/transport/http/middleware/logger.go  per-request line, exclusion list
internal/transport/http/handler/*.go          decode-failure Warn, LogAndWriteError call sites
internal/app/*/*/service.go                    logging.Logger on every best-effort call site
internal/platform/postgres/repository/*        error wrapping, NotFound sentinel translation
internal/platform/postgres/repository/transaction.go
                                                BeginTx/Commit wrapped, fn(tx) deliberately not
internal/platform/redis/, authattempt/, idempotency/, token/, password/,
internal/platform/refresh_token/, verification/
                                                error wrapping across every adapter
internal/platform/errs/refresh.go             ErrRefreshTokenNotFound
```
