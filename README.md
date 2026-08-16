# Auth Service

An authentication service built to show the decisions, not just the
endpoints: refresh token rotation with theft detection, idempotent login
under real concurrency, rate limiting that fails closed while idempotency
fails open on purpose, and an email-verification flow that deliberately
doesn't gate the rest of the system. Every non-obvious call is written
down — see [`docs/`](docs/), where each endpoint has its own Flow /
Decisions / Gaps / Tested Scenarios reference, including what's
*deliberately* not built and why.

## Endpoints

| Method | Path | Doc |
|---|---|---|
| POST | `/v1/user/register` | [`docs/register.md`](docs/register.md) |
| POST | `/v1/user/verify-email` | [`docs/email-verification.md`](docs/email-verification.md) |
| POST | `/v1/user/verify-email/resend` | [`docs/email-verification.md`](docs/email-verification.md) |
| POST | `/v1/auth/login` | [`docs/login.md`](docs/login.md) |
| GET | `/v1/auth/oauth/{provider}/start` | [`docs/oauth.md`](docs/oauth.md) |
| GET | `/v1/auth/oauth/{provider}/callback` | [`docs/oauth.md`](docs/oauth.md) |
| POST | `/v1/auth/refresh` | [`docs/refresh.md`](docs/refresh.md) |
| POST | `/v1/auth/logout` | [`docs/logout.md`](docs/logout.md) |
| GET | `/health` | [`docs/health.md`](docs/health.md) |
| GET | `/ready` | [`docs/health.md`](docs/health.md) |
| GET | `/metrics` | [`docs/metrics.md`](docs/metrics.md) |

## What's Here

- **Registration** with Gmail-style email canonicalization
  (`bayu.aditya+work@gmail.com` and `bayuaditya@gmail.com` are the same
  account), password policy enforcement, and per-IP rate limiting.
- **Login** with two-tier rate limiting (IP and credential+IP),
  constant-time dummy-hash verification against unknown accounts,
  one-active-session-per-device with a grace-period supersede for
  legitimate retries, and a required `Idempotency-Key` so a retried
  request can't mint two sessions.
- **Refresh token rotation** — single-use, chained tokens with replay
  detection: reusing an already-consumed token revokes its entire
  family, verified correct under genuinely concurrent requests, not just
  reasoned about.
- **Logout** that's idempotent by construction (not by a special case),
  verified with 20+ truly parallel identical requests against real
  Postgres.
- **Email verification** — a hashed, TTL-bound token issued at
  registration, a resend endpoint that re-delivers the *same* token
  while it's still valid (via a bounded-TTL Redis cache — the one
  deliberate exception to "raw tokens are never persisted" in this
  codebase), and a documented decision that login/refresh/logout never
  gate on verification status.
- **Audit trail** for every meaningful outcome (login, logout, refresh,
  replay detection, registration, verification), queryable in Postgres.
- **Metrics and tracing** wired to actually be useful: refresh-token
  replay is its own alertable Prometheus series instead of hiding inside
  a generic error-rate counter, rate-limit rejections are broken down by
  which limiter tripped, and traces carry `user.id`/`session.id`/
  `event.type` — all while keeping cardinality bounded and, after a bug
  caught during this build, keeping raw tokens out of the tracing
  backend entirely (see [`docs/tracing.md`](docs/tracing.md) Decisions).
- **Liveness and readiness as two separate checks**, not one — `/health`
  never touches Postgres or Redis (a dependency outage shouldn't trigger
  a pointless process restart), `/ready` actually pings both and is what
  `docker-compose.yml`'s own healthcheck targets, so a real outage shows
  up as `unhealthy` in `docker compose ps` instead of being invisible
  (see [`docs/health.md`](docs/health.md)).

## Architecture

Clean architecture with one rule that's actually enforced: **`domain`
and `app` never import `platform` or `transport` concretely — they
define interfaces, and `app.New()` wires the implementations.**

```
cmd/server/              entrypoint: flags, signals, graceful shutdown
internal/domain/<area>/  entities + the interfaces the app layer needs (no I/O)
internal/app/<area>/<usecase>/  one package per use case (login, refresh, register, ...)
internal/platform/       adapters + cross-cutting: postgres, redis, token, password,
                          logger, metrics, tracing, errs, config, authattempt
internal/transport/http/ server, router, handler/, middleware/, response/
migrations/              golang-migrate, sequentially numbered
queries/                 hand-written SQL; sqlc generates into internal/platform/postgres/sqlc
docs/                    one reference doc per endpoint, plus metrics.md/tracing.md
deployments/             docker-compose, prometheus, grafana provisioning
```

A few conventions that show up everywhere once you know to look:

- **One package per use case.** `internal/app/auth/login` exports
  `LoginService` and nothing else — no fat `service.go` holding several
  use cases.
- **Transactions are owned by the use case, not the repository.**
  `internal/app/transaction.Manager.WithinTransaction` defines the
  boundary; repositories accept the tx via `WithTx()`.
- **Errors carry a code, not a raw message.** `internal/platform/errs`
  defines domain errors; `transport/http/response/errors.go` is the
  *only* place that maps a code to an HTTP status.
- **SQL is hand-written**, not generated by an ORM — `queries/*.sql`
  compiled by `sqlc` into typed Go.

## Running Locally

Requires Docker. Everything else — Postgres, Redis, Prometheus, Grafana,
Jaeger, the migration runner, the API itself — is one command:

```bash
cp .env.example .env
make docker-up
```

That builds and starts the full stack. `deployments/docker-compose.yml`
exposes:

| Service | Address | What |
|---|---|---|
| API | `localhost:9000` | the service itself |
| Postgres | `localhost:5432` | `psql` in directly |
| Redis | `localhost:6379` | rate limiting, idempotency, verification-token cache |
| Prometheus | `localhost:9090` | scrapes `/metrics` every 15s |
| Grafana | `localhost:3000` | datasource provisioned, no dashboards shipped yet |
| Jaeger | `localhost:16686` | trace UI |
| Adminer | `localhost:8081` | Postgres UI |

```bash
curl -X POST localhost:9000/v1/user/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"Str0ngPassw0rd!"}'
```

Other useful targets — `make help` lists all of them:

```bash
make run              # run the API without Docker (needs local Postgres/Redis)
make test             # go test ./...
make run-lint         # golangci-lint
make migration name=add_something   # new migration
make migrate-up / migrate-down      # apply / roll back one
make docker-logs       # follow the API's logs
make docker-reset      # destroy data, rebuild, restart
```

## Testing

```bash
make test        # or: go test ./... -race
make run-lint     # golangci-lint, 0 issues
```

Unit tests are built around a `harness` pattern per use case (real logic,
mocked dependencies) and, for the concurrency-sensitive paths, run real
goroutines against the mocks under `-race` — login's device-slot
supersede (16 goroutines), logout's idempotent revocation (20), and
refresh's replay detection (32) each have a test that fires genuinely
parallel requests at the same mocks and asserts on the outcome, not just
the happy path. Every endpoint's doc also has a **Tested Scenarios**
section listing what was additionally verified live against the real
docker-compose stack (real Postgres, real Redis, real concurrency)
before being called done — that's where claims like "20 parallel
logouts, session revoked exactly once" come from.

## Tech Stack

Go 1.26 · PostgreSQL · Redis · sqlc · golang-migrate · Docker Compose ·
OpenTelemetry · Prometheus · Grafana · Jaeger

## Roadmap

- **gRPC transport.** The application and repository layers are already
  transport-agnostic, so this is additive: `internal/transport/grpc`
  alongside the existing HTTP handlers, no changes below the transport
  layer.
- **A second OAuth provider.** The client/provider split
  (`domain/oauth.Exchanger`) was built for more than one provider from
  the start — see [`docs/oauth.md`](docs/oauth.md) Gaps — but only
  Google is wired up, since there's no second provider yet to design
  the dispatch around.

Each endpoint doc's own **Gaps** section tracks smaller, more specific
follow-ups (e.g. no Grafana dashboards ship yet, failure-path audit
events are incomplete for a couple of endpoints) — deliberately not
duplicated here. Decisions that span multiple endpoints or predate any
single one live in [`docs/adr/`](docs/adr/) instead.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
