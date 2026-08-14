# Logout

`POST /v1/auth/logout`

Terminates the session tied to the presented refresh token: revokes the
session and its entire refresh-token family. No `Idempotency-Key`
required — see Decisions for why this endpoint's own idempotency
guarantee makes that unnecessary, unlike login.

## Flow

`internal/app/auth/logout/service.go` — `Service.Handle`

1. **Locate the presented token.** Hash + lookup by hash, same as
   refresh. Not found → `ErrInvalidRefreshToken`, audited.

2. **Resolve its owning session.** `FindByID(current.SessionID)`. Not
   found → `ErrInvalidRefreshToken`, audited with the session ID (never
   a user ID — the failed lookup is exactly what leaves it unresolved;
   see `docs/refresh.md` Decisions for the bug this pattern avoids
   repeating).

3. **Revoke the session and its whole refresh-token family.** Single
   transaction: `Session.Revoke(RevokeUserLogout)`, then
   `RefreshToken.RevokeFamily(RevokeReasonLogout)`. No
   expiry/revocation/consumed checks on the presented token or session
   beforehand — unlike refresh, which validates all three before doing
   anything. Logout's job is strictly weaker: "make sure this session is
   dead," which an already-expired, already-consumed, or
   already-revoked token still correctly identifies. See Decisions.

4. **Publish audit event.** `LOGOUT`, `success=true`, with
   userID/sessionID/IP/UA.

## Idempotency and Concurrency

Unlike login, this endpoint needs no Idempotency-Key mechanism: it's
already naturally idempotent by construction, verified under real
concurrency, not just reasoned about.

`Session.Revoke` and `RefreshToken.RevokeFamily` are both guarded at the
SQL level with `WHERE revoked_at IS NULL` (see
`internal/platform/postgres/repository/session/repository.go` and
`queries/refresh_token.sql`). A second revoke of an already-revoked row
matches zero rows and returns success rather than an error or a
clobbered row — the original revocation's reason and timestamp survive
untouched. This is what makes flow step 3 safe to run unconditionally on
every call instead of checking state first.

Verified live against real Postgres: 20 genuinely parallel curl requests
with the identical refresh token all returned 204; the session ended up
revoked exactly once, with the correct `USER_LOGOUT` reason (not
overwritten by a later racer); all 20 requests were independently
audited with `session_id` and `ip_address` populated. See
`TestService_Handle_ConcurrentLogoutsAllSucceed` for the equivalent at
the unit level (20 goroutines, run under `-race`).

The no-checks design in flow step 3 also means an already-expired token
still logs out successfully: expiry is irrelevant to logout, only
existence of the token row is required to identify the session/family to
kill.

## Decisions

- **Logout does not gate on `EmailVerifiedAt`.** An unverified account
  can log out exactly like a verified one — deliberate, same reasoning
  as login and refresh; see `docs/email-verification.md` Decisions.
  Verified live: an unverified account logged out successfully.

- **No Idempotency-Key requirement, unlike login.** Login needs one
  because a retried login mints an entirely new session — without
  idempotency, two retries collide into two sessions fighting over one
  device slot (see `docs/login.md`). Logout has no equivalent
  resource-creation step to duplicate; "logged out" is a single end
  state every caller converges on regardless of how many times they ask
  for it. Requiring a key here would add API surface with no
  corresponding problem to solve.

- **No expiry/revocation checks before acting** (flow step 3).
  Deliberate, not a shortcut: checking first and acting second would
  only reintroduce a race the idempotent-revoke design already closes
  for free, and would reject exactly the case (an already-expired
  token) that a client calling logout on app teardown is most likely to
  present.

## Capabilities

- Idempotent revocation, safe under genuine concurrent/duplicate calls
  (verified, not assumed — see Idempotency and Concurrency above).
- Revokes the whole refresh-token family, not just the presented token —
  a stolen-but-not-yet-used sibling token stops working too.
- Full audit trail: `LOGOUT` (success and failure), carrying
  `session_id`, IP, and user agent — also exported as
  `auth_events_total{type="LOGOUT",success}` (see `docs/metrics.md`;
  success and failure share the same event type here, same as they do
  in the audit log, so the `success` label is what tells them apart).

## Gaps

- **"Logout all devices" does not exist.** `audit.EventLogoutAll` is
  defined but unused — see `docs/register.md` for the broader pattern of
  scaffolded-but-unwired constants in this codebase. This endpoint only
  ever terminates the one session tied to the presented refresh token.
  Building a real logout-all would need a way to enumerate a user's
  active sessions, which doesn't exist yet either (no session-listing
  endpoint). Flagged as a natural next capability if device management
  becomes a requirement.

## API Contract

**Request**

```
POST /v1/auth/logout
Content-Type: application/json

{
  "refresh_token": string  // required
}
```

**Success — `204 No Content`**

Empty body.

**Errors**

| Status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | malformed JSON body |
| 401 | `AUTH_INVALID_REFRESH_TOKEN` | unknown token, or its session is gone — a client cannot distinguish these |
| 500 | `INTERNAL_ERROR` | unexpected failure |

Calling this endpoint twice with the same token, or many times
concurrently, still returns 204 every time — see Idempotency and
Concurrency above.

## Tested Scenarios

Unit — `internal/app/auth/logout/service_test.go`
(`go test ./internal/app/auth/logout/... -race`):

- success: session revoked with `USER_LOGOUT`, family revoked with
  `LOGOUT`, audited
- audit event carries the correct user ID, session ID, IP, and user
  agent
- calling `Handle` twice sequentially with the same token succeeds both
  times (idempotency)
- 20 concurrent goroutines calling `Handle` with the identical token:
  all succeed, all independently audited (run under `-race`)
- unknown token, session gone, transaction failure, session-revoke
  failure, family-revoke failure — all rejected/propagated correctly

e2e — against the real docker-compose stack:

- register → login → refresh → logout, full lifecycle
- logout with a garbage/unknown token → 401
- 20 genuinely parallel curl requests with the identical refresh token:
  all 204, session revoked exactly once with the correct reason
  preserved, 20 independently audited rows all with `session_id` and
  `ip_address` populated
- double logout, logout with malformed JSON, logout with an empty
  `refresh_token`, refresh attempted against a logged-out session
  correctly rejected

## Related Files

```
internal/app/auth/logout/service.go         use case
internal/app/auth/logout/event.go           LOGOUT event constructors
internal/domain/session/repository.go       Revoke (guarded, idempotent)
internal/domain/refresh_token/repository.go RevokeFamily (guarded, idempotent)
internal/platform/postgres/repository/session/repository.go
                                             Revoke SQL, revoked_at IS NULL guard
queries/refresh_token.sql                   RevokeRefreshTokenFamily
internal/transport/http/handler/logout.go   HTTP handler
internal/transport/http/router.go           POST /v1/auth/logout
```
