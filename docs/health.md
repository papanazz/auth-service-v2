# Health

`GET /health` — liveness. `GET /ready` — readiness. Both unauthenticated
(see Gaps), both handled by `internal/health.Handler`.

Like `docs/metrics.md` and `docs/tracing.md`, this is a cross-cutting doc,
not a per-endpoint one.

## Endpoints

### `/health` — liveness

Answers exactly one question: is this process able to respond to a
request at all. Always `200 {"data":{"status":"ok"}}` if the HTTP server
is up — it makes no calls to Postgres or Redis, on purpose (see
Decisions). There is nothing to configure and nothing that can make this
endpoint slow.

### `/ready` — readiness

Answers a different question: can this instance actually serve traffic
right now. Pings Postgres (`pgxpool.Pool.Ping`) and Redis
(`redis.Cache.Health`, itself a `PING`) concurrently, each bounded by a
2-second timeout so one hung dependency can't leave the request hanging
indefinitely. `200` only if both succeed; `503` if either fails, with a
per-dependency breakdown:

```json
{
  "data": {
    "status": "ready",
    "checks": {
      "database": { "status": "ok", "duration_ms": 3 },
      "redis":    { "status": "ok", "duration_ms": 1 }
    }
  }
}
```

On failure, the failing dependency's `status` becomes `"error"` and the
top-level `status` becomes `"not_ready"` — never the raw error (a
connection-refused message can carry a hostname or port); the real error
is logged server-side instead (`[Ready] dependency check failed`, with
the dependency name and the actual error, at `internal/health/health.go`).

## Decisions

- **Liveness and readiness are two different endpoints, not one.** They
  answer different questions with different consequences for whoever's
  polling: a liveness failure means "restart this process," a readiness
  failure means "stop routing traffic here, but don't touch the
  process." Collapsing them into one — which is what `/health` used to
  be before this change, an unconditional `200` regardless of Postgres
  or Redis state — meant a real Postgres or Redis outage was invisible
  to the one check that existed. `docker inspect` reported the API
  container `healthy` throughout a Redis outage tested during this
  change, purely because nothing was actually checking.

- **Liveness deliberately does not check dependencies.** If it did, a
  Postgres blip would make an orchestrator (Kubernetes, Compose,
  anything watching this check) restart the API process — which fixes
  nothing, since the process was never the problem, and adds a second
  failure (a cold restart, dropped connections, a cache flush) on top of
  the first. Readiness is the correct place to react to a dependency
  outage: pull the instance out of rotation and leave it running so it
  recovers the moment the dependency does.

- **Docker Compose's own `healthcheck:` now points at `/ready`, not
  `/health`.** Compose has one healthcheck per container, not
  Kubernetes's separate liveness/readiness probes, so it has to pick
  one — and the one that actually reflects "can this container serve
  real traffic" is readiness. Pointing it at the old `/health` would
  have kept `docker compose ps` reporting `healthy` through any Postgres
  or Redis outage, the exact gap this doc exists to close. Verified
  live: stopping the Redis container flips `docker inspect
  bayu.auth.http`'s health status to `unhealthy` within one interval
  cycle; restarting Redis recovers it. Same result stopping/restarting
  Postgres independently.

- **Checks run concurrently, each under its own timeout, not
  sequentially with one shared deadline.** Two dependencies checked
  serially means the worst case is the sum of both timeouts; concurrent
  checks bound the worst case to the slower of the two. `Ready`'s
  30-line loop over a buffered channel was chosen over pulling in
  `errgroup` for two checks — the dependency (already indirect via
  something else in `go.mod`) wasn't worth promoting to direct for
  something this small.

- **The response body never carries a raw error string.** Every other
  error-shaped response in this API goes through
  `internal/platform/errs` and a deliberately chosen message
  (`docs/login.md`, `docs/refresh.md`, ...). A dependency ping failure
  has no such curated message — it's whatever the driver returned,
  which can include internal hostnames or ports — so it's logged, not
  echoed back to an unauthenticated caller.

- **`DatabasePinger`/`CachePinger` are two narrow interfaces, not one
  shared shape.** `*pgxpool.Pool` already exposes `Ping(ctx) error`;
  `*redis.Cache` already exposes `Health(ctx) error`
  (`internal/platform/redis/redis.go`, itself unused before this
  change). Renaming either to force a common method name would be
  churn for no benefit — `internal/health` is free to depend on
  `platform` concretely (it isn't a `domain` or `app` package under the
  dependency-inversion rule in the top-level `CLAUDE.md`), and two
  one-method interfaces are enough to mock both dependencies in tests
  without touching real infrastructure.

## Capabilities

- A real Postgres or Redis outage now surfaces as a `503` from `/ready`
  and an `unhealthy` container in `docker compose ps` — verified live in
  both directions (outage and recovery) for both dependencies
  independently.
- Liveness stays fast and dependency-free, so a downstream outage can
  never trigger an unnecessary process restart.
- A hung dependency can't hang the readiness check itself — bounded by a
  2s timeout per check, verified with a test dependency that blocks
  until its context is canceled.
- No raw error text (hostnames, ports, driver-specific messages) is ever
  exposed through either endpoint.

## Gaps

- **Neither endpoint requires authentication** — same class of gap
  already accepted for `/metrics` (`docs/metrics.md`) and Jaeger's UI
  (`docs/tracing.md`): anyone reaching port 9000 can poll `/ready` and
  see which dependency (if any) is down, though never why in detail. A
  real deployment would put both behind the same internal-only boundary
  as the rest of the observability surface.
- **No separate check for "is this instance's config sane"** (e.g. a
  bad JWT secret) — `/ready` only verifies the two live network
  dependencies. Config validation already happens at startup
  (`config.Config.Validate()`, `internal/platform/config`) and fails
  fast before the server ever binds a port, so a bad config never
  reaches a state where `/ready` would need to catch it — this is
  flagged here only in case that guarantee ever changes.
- **`/ready`'s 2-second per-check timeout is a fixed constant**, not
  configurable via env var like most of this service's other tunables
  (`internal/platform/config`). Reasonable default for a service this
  size; would want to be a `HealthCheckTimeout` config field if
  Postgres/Redis latency profiles ever diverge meaningfully from what
  this assumes.

## Tested Scenarios

Unit — `internal/health/health_test.go`
(`go test ./internal/health/... -race`):

- `/health` returns `200` even when both dependency pingers are set to
  fail — proves liveness truly never touches them
- `/ready` returns `200` with `status:"ready"` and both checks `"ok"`
  when both dependencies succeed
- `/ready` returns `503` with `status:"not_ready"` when only the
  database fails — and confirms Redis's check still correctly reports
  `"ok"`, not masked by the other failure
- the same, mirrored, for Redis failing alone
- the raw error text is never present in the response body
- a dependency that blocks until its context is canceled still returns
  within the configured timeout, with that check reported as failed —
  proves the timeout is real, not just documented

e2e — against the real docker-compose stack:

- all healthy: `/health` → `200`; `/ready` → `200` with both checks
  `"ok"`, `duration_ms` in the low single digits
- `docker stop` the Redis container: `/health` stays `200`; `/ready`
  immediately shows `redis:"error"` (database still `"ok"`) and returns
  `503`; `docker inspect bayu.auth.http` flips to `unhealthy` within one
  healthcheck interval cycle
- `docker start` Redis again: `/ready` returns to `200` immediately;
  the container's health status recovers on the next check
- the same cycle repeated independently for the Postgres container, with
  the same result

## Related Files

```
internal/health/health.go        Handler: Health (liveness), Ready (readiness)
internal/app/app.go               Redis exposed on Application for the handler
internal/transport/http/router.go GET /health, GET /ready
internal/platform/redis/redis.go  Cache.Health (PING) — existed, was unused before this
deployments/docker-compose.yml    healthcheck: now targets /ready
```
