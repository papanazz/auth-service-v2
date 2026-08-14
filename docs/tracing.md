# Tracing

Distributed tracing via OpenTelemetry, exported over OTLP/gRPC
(`OTEL_EXPORTER_OTLP_ENDPOINT`, default `localhost:4317`) to the bundled
`deployments/jaeger` container. Jaeger's UI is on `:16686`, unauthenticated
(see Gaps).

Like `docs/metrics.md`, this is not a per-endpoint doc — it's a
cross-cutting look at what gets traced across all six endpoints, and why.

## Tracing

### HTTP — one root span per request

`internal/transport/http/middleware/tracing.go` wraps every route (except
`/metrics`) in `otelhttp.NewHandler`, named `<method> <chi-route-pattern>`
(e.g. `POST /v1/auth/login`, not the literal path — so `/v1/auth/login`
for every caller is one operation in Jaeger, not one per request). The
standard `otelhttp` semantic-convention attributes are attached
automatically: `http.request.method`, `http.response.status_code`,
`client.address`, `user_agent.original`, request/response body sizes, and
so on.

### Postgres and Redis — every query and command, automatically

`platform/postgres.New` installs `otelpgx.NewTracer()` as the pool's
`pgx.QueryTracer`; `platform/redis.New` installs
`redisotel.InstrumentTracing`. Both piggyback on the context already
carrying the HTTP root span (every repository method takes `ctx` and
passes it straight through — no wiring needed per call site), so every
SQL statement and every Redis command shows up as a child span with no
per-repository instrumentation code anywhere in this codebase. Confirmed
live: a single `POST /v1/auth/login` trace shows `query begin isolation
level read committed`, the individual `SELECT`/`INSERT`/`UPDATE`
statements inside `LoginService.Handle`'s transaction, `query commit`,
and the two `get`/one `evalsha` Redis calls from the two rate limiters —
all as children of the one HTTP span.

### `event.type`, `event.success`, `user.id`, `session.id` — on the request span

`internal/platform/tracing.AuditPublisher` decorates the same shared
`audit.Publisher` instance the metrics decorator wraps
(`docs/metrics.md`): every `Publish` call attaches the event's type,
success, and (when known) user/session IDs to the span already active in
`ctx` — the HTTP root span — before forwarding to the real publisher.
Composed once in `internal/app/app.go`, so no use case has any
tracing-specific code. Verified live: a successful login's trace carries
`event.type=LOGIN_SUCCESS`, `event.success=true`, `user.id=<uuid>`,
`session.id=<uuid>` directly on the `POST /v1/auth/login` span — findable
in Jaeger's own attribute search, not just by first finding a `trace_id`
in the log backend.

### `request.id`

Set directly in `middleware.Tracer` from the request-scoped ID
`middleware.RequestID` generates, ties a trace to the exact structured
log lines for that request (`internal/platform/logger` — see
Correlation).

## Correlation

Every structured log line already carries `trace_id`
(`logger.GetTraceID`, which reads the active span's trace ID out of
`ctx`) alongside `request_id` and `log_id`. Between that and the span
attributes above, a single failed request can be found from any of three
directions — a Jaeger search by `user.id` or `event.type`, a log search
by `request_id`, or pasting a log line's `trace_id` into Jaeger — without
needing to have captured the right identifier up front.

## Decisions

- **Redis command *arguments* are not captured, unlike Postgres's SQL
  *statement text*.** `platform/redis.New` passes
  `redisotel.WithDBStatement(false)` explicitly — the tracing hook's
  default (`dbStmtEnabled: true`) captures every argument of every
  command as the `db.statement` attribute, not just the command name.
  For this client that meant the raw email-verification token
  (`platform/verification.RedisCache.StoreRawToken` — the one
  deliberate exception to "raw tokens are never persisted," meant to
  stay bounded to Redis alone, see `docs/email-verification.md`) and the
  full cached login response (access token + raw refresh token,
  `platform/idempotency.Store.Save`) would otherwise appear verbatim in
  every trace shipped to an unauthenticated Jaeger UI. Postgres needed
  no equivalent change: `otelpgx.NewTracer()` only captures SQL bind
  values if `WithIncludeQueryParameters()` is passed, which this
  codebase never does, so query *text* (with `$1`/`$2` placeholders) is
  safe by default while Redis's default was not. Verified live, before
  and after: traces captured before this fix show the raw
  base64-encoded access/refresh token pair as a `db.statement` value on
  a `set` span; a trace captured after show the identical operation
  (`set`) with zero `db.statement` attribute.

- **Business context is attached via a decorator around
  `audit.Publisher`, not scattered `span.SetAttributes` calls in each
  use case.** Identical reasoning to `docs/metrics.md`'s decision for
  the metrics decorator: every meaningful outcome already flows through
  one `audit.Publish` call, so that is the one place this needs to be
  added, and the two decorators are kept separate (`platform/metrics`
  vs. `platform/tracing`) rather than merged into one, since they
  instrument two unrelated systems and have no reason to share code
  beyond wrapping the same interface.

- **Only `user.id`/`session.id`/`event.type`/`event.success` are
  attached, not `audit.Event.Reason`.** Same boundary `docs/metrics.md`
  draws for Prometheus labels: several `Reason` values exist
  specifically so two different situations produce an identical outward
  signal (login's unknown-account and wrong-password paths). A span
  attribute is observable the same way a label is — this is a narrower
  cut than what Postgres's own query spans already reveal per trace
  (which branch ran is visible from which `SELECT`/`UPDATE` statements
  executed), but there's no reason to also spell it out redundantly in
  an attribute.

- **Attributes are attached to the existing HTTP root span, not a new
  child span.** `trace.SpanFromContext(ctx)` in
  `platform/tracing.AuditPublisher.Publish` resolves to whatever span is
  already active — the root span for every real request, since nothing
  between the handler and `audit.Publish` opens a child span of its own.
  Simpler than minting a dedicated span only to attach four attributes
  to it, and keeps the attributes searchable directly on the span
  everything else (HTTP status, latency, `request.id`) already lives on.

- **`sdktrace.AlwaysSample()`** — every request is traced, no sampling.
  Correct for a service at this traffic volume and for a portfolio
  deployment where the point is to demonstrate the instrumentation; see
  Gaps for why this wouldn't survive real production volume unchanged.

## Capabilities

- Every SQL statement and Redis command in a request's path is traced
  automatically, correctly parented under that request's root span, with
  zero per-repository instrumentation code.
- A trace, a log line, and now a specific user/session/outcome are all
  reachable from each other — see Correlation.
- Redis span attributes are provably free of raw secrets and credential
  material — verified live, not just reasoned about (see Decisions).
- 100% sampling means no failed or slow request is ever missing from
  Jaeger because it didn't get sampled — every incident has a trace.

## Gaps

- **`AlwaysSample()` does not scale to real production traffic.** Fine
  today; at meaningfully higher volume this would need a
  probabilistic or tail-based sampler (keep-if-error / keep-if-slow is
  the usual shape) so the trace backend's storage and Jaeger's own query
  performance don't degrade under 100% capture.
- **Jaeger's UI is unauthenticated**, same class of gap as `/metrics`
  (`docs/metrics.md` Gaps) — anyone reaching port 16686 can browse every
  trace, including the `user.id`/`session.id` attributes this feature
  adds. Lower severity than the pre-fix Redis leak (no raw tokens after
  this change), but a real deployment would put this behind the same
  network boundary as the rest of the observability stack, not exposed
  publicly.
- **No span for Argon2id password hashing.** It's deliberately expensive
  (`platform/password/argon2id.go`: 64 MiB memory, 3 iterations, 2
  threads) and directly gates login/register throughput, but that CPU
  time is currently invisible in a trace — it just looks like unexplained
  latency between the DB spans on either side of it. Considered as part
  of this review and deliberately deferred rather than built.
- **No custom span for the use-case's own decision points** (rate-limit
  check, password verification, transaction boundary) beyond what
  Postgres/Redis auto-instrumentation already produces. The SQL/Redis
  spans are a reasonable proxy for where time goes today; a use case
  with expensive non-I/O logic beyond password hashing would be the
  trigger to revisit this.

## Related Files

```
internal/platform/tracing/tracing.go           TracerProvider init, OTLP exporter
internal/platform/tracing/audit_publisher.go    AuditPublisher decorator
internal/transport/http/middleware/tracing.go   HTTP root span, request.id
internal/platform/postgres/postgres.go          otelpgx wiring
internal/platform/redis/redis.go                redisotel wiring, WithDBStatement(false)
internal/platform/logger/context.go             GetTraceID — log/trace correlation
internal/app/app.go                             wiring: both audit decorators composed once
deployments/docker-compose.yml                  jaeger service, OTEL_EXPORTER_OTLP_ENDPOINT
```
