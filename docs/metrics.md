# Metrics

`GET /metrics` — Prometheus exposition format, scraped by the bundled
`deployments/prometheus` container every 15s. Unauthenticated (see Gaps).

This is not a per-endpoint doc like `docs/login.md` — it's a cross-cutting
look at what each of the six endpoints (`register`, `login`, `refresh`,
`logout`, `verify-email`, `verify-email/resend`) needs observable, and
why.

## Metrics

### `http_requests_total{method, path, status}`

Every request, counted by outcome. Since HTTP status is a label, this
already breaks failures down by *category* wherever the status codes
themselves differ — `docs/login.md`'s API Contract table maps `401`
invalid credentials, `403` locked account, `409` device conflict, and
`429` rate limited to distinct statuses on the same path, so all four
are already independently visible here without any endpoint-specific
instrumentation.

### `http_request_duration_seconds{method, path}`

Latency histogram per endpoint.

Both of the above are recorded generically by
`internal/transport/http/middleware/metrics.go`, ahead of any
routing to a specific handler — every endpoint gets them for free.

### `auth_events_total{type, success}`

Mirrors every `audit.Event` published anywhere in the app layer —
`LOGIN_SUCCESS`/`LOGIN_FAILED`, `TOKEN_REFRESH`/`TOKEN_REFRESH_FAILED`/
`TOKEN_REUSE_DETECTED`, `LOGOUT`, `USER_REGISTERED`, `EMAIL_VERIFIED`,
`VERIFICATION_EMAIL_SENT` — through a decorator around the single
`audit.Publisher` instance shared by all six use cases
(`internal/platform/metrics.AuditPublisher`, composed once in
`internal/app/app.go`). Every `Publish` call increments this counter
before forwarding to the real (Postgres) publisher.

The endpoint's own HTTP status usually already distinguishes success
from failure, but refresh has one pair that deliberately does not:
an ordinary invalid/expired/unknown token
(`AUTH_INVALID_REFRESH_TOKEN`) and a **replayed, already-consumed
token** (`AUTH_REFRESH_TOKEN_REPLAY`) both return `401` on purpose
(`internal/transport/http/response/errors.go`'s comment: "returning
500 would both mislead the client and page an on-call engineer for
what is a client-side event"). That is the right call for the
client-facing status code, but it also means `http_requests_total`
alone cannot tell "a client retried a stale token" (routine, high
volume) from "someone replayed a token that was already used" (the
signature of a stolen refresh token — `docs/refresh.md` flow step 3).
`auth_events_total{type="TOKEN_REUSE_DETECTED"}` is its own time
series regardless, so
`rate(auth_events_total{type="TOKEN_REUSE_DETECTED"}[5m]) > 0` is a
real, pageable alert. Verified live: replaying a consumed refresh
token shows `TOKEN_REUSE_DETECTED` as a series distinct from
`TOKEN_REFRESH_FAILED`.

### `auth_rate_limit_rejections_total{limiter}`

Counts requests rejected by `authattempt.RedisTracker` — the sole
implementation of `auth.AttemptTracker`, shared by register, login, and
resend-verification — labeled by which of the four limiters tripped
(`auth:register:ip`, `auth:login:ip`, `auth:login:credential`,
`auth:resend-verification:ip`; see `internal/platform/authattempt/key.go`).
The label is the rate-limit key's fixed prefix, never its identifying
suffix (an IP address or a SHA-256 credential hash) — see Decisions.

Login runs two of these limiters behind one endpoint and one `429`, so
`http_requests_total{path="/v1/auth/login",status="429"}` alone cannot
tell "one IP hammering many different accounts" (IP-scoped, looks like
mass credential stuffing or a scanner) apart from "many attempts
against one specific account" (credential-scoped, looks like a
targeted attack on one user) — a different incident either way, same
number. `auth_rate_limit_rejections_total` splits them. Verified live:
tripping the register-IP, login-credential, and resend-verification-IP
limiters independently produced three distinct series, each with a
plausible count, no IP address or hash anywhere in the label set.

## Per-Endpoint Coverage

| Endpoint | Generic | `auth_events_total` types | `auth_rate_limit_rejections_total` limiter |
|---|---|---|---|
| `POST /v1/user/register` | requests, latency, status | `USER_REGISTERED` (success only — see Gaps) | `auth:register:ip` |
| `POST /v1/auth/login` | requests, latency, status (401/403/409/429 already distinct) | `LOGIN_SUCCESS`, `LOGIN_FAILED` | `auth:login:ip`, `auth:login:credential` |
| `POST /v1/auth/refresh` | requests, latency, status | `TOKEN_REFRESH`, `TOKEN_REFRESH_FAILED`, **`TOKEN_REUSE_DETECTED`** | none (deliberately not rate-limited — `docs/refresh.md` Decisions) |
| `POST /v1/auth/logout` | requests, latency, status | `LOGOUT` (success and failure both use this type; see `internal/app/auth/logout/event.go`) | none (deliberately, same doc) |
| `POST /v1/user/verify-email` | requests, latency, status | `EMAIL_VERIFIED` (success only — see Gaps) | none (the token itself is the rate limit — see `docs/email-verification.md`) |
| `POST /v1/user/verify-email/resend` | requests, latency, status | `VERIFICATION_EMAIL_SENT` (real sends only, not the no-op paths — deliberate, see `docs/email-verification.md` Decisions) | `auth:resend-verification:ip` |

## Decisions

- **A decorator around the existing `audit.Publisher`, not a metrics
  dependency added to six use-case constructors.** Every meaningful
  business outcome already flows through one `audit.Publish` call — the
  decorator is the one place that's true, so it's the one place metrics
  need to be added. The alternative (inject `*metrics.Metrics` into
  `register.NewService`, `login.NewService`, ... individually) would
  mean six more constructor parameters and six more places to forget to
  wire one in — exactly the class of bug `internal/app/policy.go`'s
  `TestNew*SecurityPolicy_WiresEveryField` reflection tests exist to
  catch for security policy fields. No use-case file changes for this
  feature. `internal/platform/tracing.AuditPublisher` (`docs/tracing.md`)
  wraps the same shared instance the same way, for the same reason, to
  attach `event.type`/`event.success`/`user.id`/`session.id` to the
  active trace span — a separate decorator rather than folding tracing
  into this one, since the two instrument unrelated systems.

- **Labeled by `type`/`success` only — never by `audit.Event.Reason`.**
  Several `Reason` values exist specifically so two different situations
  produce an identical outward signal: login's unknown-account and
  wrong-password paths both return `INVALID_CREDENTIALS` and both run
  the dummy Argon2 verification (`docs/login.md` Capabilities) so a
  timing or response difference can't be used to enumerate accounts. A
  Prometheus label is just as observable as an HTTP response body or
  timing — splitting `LOGIN_FAILED` by `Reason` would quietly reopen the
  exact side channel that design closes, just in a different place.
  `type`+`success` preserves the same granularity the HTTP status codes
  already expose (see the coverage table above) without adding a new
  one.

- **The rate-limit label is a parsed, fixed key *prefix*, never the raw
  key.** `authattempt.RedisTracker.Check` receives the full key (e.g.
  `auth:login:credential:<sha256-hash>`) — using it directly as a label
  would create one Prometheus time series per caller, an unbounded and
  ever-growing set that would eventually take down the scrape endpoint
  or the Prometheus TSDB. `limiterFromKey` keeps only the first three
  `:`-separated segments, which is exactly the fixed, small vocabulary
  defined in `key.go` (four values today) regardless of how many
  distinct IPs or accounts ever hit it. A key with fewer than three
  segments — not producible by this package today, but a defensive
  floor for any future limiter — falls back to `"unknown"` rather than
  ever passing the raw key through.

- **The metric is recorded before forwarding to the real publisher, not
  after.** `AuditPublisher.Publish` increments the counter unconditionally,
  then calls the wrapped (Postgres) publisher and returns whatever it
  returns. If the durable audit write fails, the metric still reflects
  what the app layer decided happened — arguably more valuable during a
  Postgres outage, not less, and consistent with every call site already
  treating `audit.Publish` as best-effort (`_ = s.audit.Publish(...)`).

- **`RedisTracker` takes a `*metrics.Metrics` constructor argument
  directly, rather than being wrapped in a decorator like
  `audit.Publisher` is.** Unlike `audit.Publisher`, `auth.AttemptTracker`
  has exactly one production implementation and one construction site
  (`app.go`) — a decorator would only add an indirection layer around a
  1:1 relationship. Consistent, not dogmatic: the pattern fits each case
  rather than one mechanism being forced onto both.

## Capabilities

- `TOKEN_REUSE_DETECTED` — the single highest-value security signal in
  this service — is its own alertable Prometheus series, not just an
  audit-log row.
- Every one of the six endpoints' meaningful outcomes is visible in
  `auth_events_total`, with no metrics-specific code in any use case.
- All four rate limiters are independently observable
  (`auth_rate_limit_rejections_total{limiter}`), letting an IP-scoped
  attack be told apart from a credential-scoped one on the same login
  endpoint.
- Both metrics are provably cardinality-bounded: `auth_events_total` by
  the fixed, closed set of `audit.EventType` constants (12 today) × 2
  (`success`); `auth_rate_limit_rejections_total` by the fixed set of
  limiter key prefixes (4 today) — neither grows with traffic, user
  count, or IP diversity.

## Gaps

- **`/metrics` is unauthenticated.** Anyone who can reach port 9000 can
  scrape it. Low severity for the data exposed today (bounded-cardinality
  counters and histograms, no PII, no raw IPs/hashes — the whole point
  of the label design above), but a real deployment behind a public
  ingress would want this on an internal-only listener or behind the
  same network boundary as `/health`, not exposed the same way as the
  public API surface.
- **`USER_REGISTERED` and `EMAIL_VERIFIED` are success-only audit
  events** (`docs/register.md` Gaps, `docs/email-verification.md`), so
  `auth_events_total` inherits the same asymmetry: a failed registration
  or a rejected verification token shows up in `http_requests_total`'s
  status breakdown but not as its own `auth_events_total` series. Fixing
  this means adding the missing failure-path audit events first — a
  metrics-layer decorator can only record what the app layer actually
  publishes.
- **No product/funnel metric for register→verify conversion.** It's
  derivable today from `auth_events_total{type="USER_REGISTERED"}` vs
  `auth_events_total{type="EMAIL_VERIFIED"}` in Grafana directly (a
  ratio panel needs no new instrumentation), so this wasn't built as a
  separate counter — flagged here in case a dashboard ever wants it
  pre-computed server-side instead.
- **No Grafana dashboard ships with these metrics** —
  `deployments/grafana/provisioning` only provisions the datasource, no
  dashboards. Both metric families are dashboard-ready (bounded labels,
  meaningful names) but none exists in this repo today.

## API Contract

**Request**

```
GET /metrics
```

No authentication required (see Gaps).

**Success — `200 OK`**

Prometheus text exposition format. Relevant excerpt (after a
registration, a login, a login failure, and a rate-limit trip):

```
# HELP auth_events_total Total audited authentication/account events, by type and outcome
# TYPE auth_events_total counter
auth_events_total{success="false",type="LOGIN_FAILED"} 1
auth_events_total{success="true",type="LOGIN_SUCCESS"} 1
auth_events_total{success="true",type="USER_REGISTERED"} 1

# HELP auth_rate_limit_rejections_total Total requests rejected by a rate limiter, by which limiter tripped
# TYPE auth_rate_limit_rejections_total counter
auth_rate_limit_rejections_total{limiter="auth:register:ip"} 3
```

## Tested Scenarios

Unit — `internal/platform/metrics/audit_publisher_test.go`
(`go test ./internal/platform/metrics/... -race`):

- a published event both increments `auth_events_total{type,success}`
  and forwards unchanged to the wrapped publisher
- success and failure events land in different label combinations of the
  same counter, never mixed
- the counter still increments even when the wrapped (Postgres)
  publisher's `Publish` call fails — the metric doesn't depend on the
  durable write succeeding

Unit — `internal/platform/authattempt/service_test.go`
(`go test ./internal/platform/authattempt/... -race`):

- `limiterFromKey` maps each of the four real key constructors
  (`LoginIP`, `LoginCredential`, `RegisterIP`, `ResendVerificationIP`) to
  its expected fixed prefix
- a malformed/too-short key falls back to `"unknown"` rather than being
  passed through
- the returned label is always shorter than the input key — the
  identifying suffix never survives

e2e — against the real docker-compose stack:

- registered, logged in successfully, and logged in with a wrong
  password: `/metrics` shows `auth_events_total{type="USER_REGISTERED",success="true"}`,
  `{type="LOGIN_SUCCESS",success="true"}`, and
  `{type="LOGIN_FAILED",success="false"}` as three distinct series
- tripped all four rate limiters (register IP, login IP, login
  credential, resend-verification IP) independently:
  `auth_rate_limit_rejections_total` showed `auth:register:ip`,
  `auth:login:credential`, `auth:resend-verification:ip` each with a
  plausible count and no IP address or credential hash anywhere in the
  label set
- rotated a refresh token once (success), then replayed the same
  now-consumed token: `/metrics` showed `TOKEN_REUSE_DETECTED` as its
  own series, distinct from `TOKEN_REFRESH_FAILED` — exactly the
  distinction this metric exists to make

## Related Files

```
internal/platform/metrics/metrics.go          Metrics struct, registration
internal/platform/metrics/audit_publisher.go   AuditPublisher decorator
internal/platform/authattempt/service.go       RedisTracker, limiterFromKey
internal/platform/authattempt/key.go           the four rate-limit key constructors
internal/transport/http/middleware/metrics.go  generic HTTP metrics
internal/domain/audit/event.go                 EventType constants, Event struct
internal/app/app.go                            wiring: both decorators composed once
deployments/prometheus/prometheus.yml          scrape config
deployments/grafana/provisioning/              datasource only, no dashboards — see Gaps
```
