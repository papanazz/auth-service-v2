# Login

`POST /v1/auth/login`

Authenticates an email+password credential for one device and returns an
access token (short-lived JWT) plus a refresh token (long-lived, rotating,
persisted hashed). Requires an `Idempotency-Key` header (see Idempotency).

## Flow

`internal/app/auth/login/service.go` — `LoginService.Handle`

1. **Normalize and validate input.** `user.NormalizeEmail()` lowercases
   and trims the address, and — for a known provider (currently Gmail) —
   collapses dots and a `+tag` in the local part to their canonical form.
   Shared with register, so both endpoints agree on what "the same
   email" means (see `docs/register.md`). `Validate()` (`validator.go`)
   additionally requires a non-empty password, a non-empty `device_id`,
   and a `device_type` that is one of `session.DeviceType`'s known
   values (`WEB`/`ANDROID`/`IOS`).

2. **Rate limit check.** Two independent Redis-backed windows
   (`platform/authattempt`), checked before touching the database:
   per-IP, and per credential+IP pair. Both fail closed — a Redis error
   aborts the request rather than letting an unlimited-rate caller
   through. See Decisions for why idempotency (a different Redis-backed
   check on this same endpoint) makes the opposite choice.

3. **Find account.** `FindByEmail`. On failure, a dummy Argon2
   verification still runs (see Capabilities) before returning
   `ErrInvalidCredentials`, so an unregistered email takes the same time
   as a wrong password.

4. **Verify password.** Argon2id constant-time comparison. On failure:
   `RecordFailure` against the credential rate limiter, audit
   `LOGIN_FAILED`, return `ErrInvalidCredentials`. On success: reset the
   credential limiter immediately (a legitimate login should not carry
   forward an innocent typo's rate-limit weight).

5. **Account status check.** `account.CanLogin(now)` after password
   verification, not before: revealing "this account is locked" to a
   caller who has not yet proven they know the password would hand out
   account-existence information for free. A failure here does not count
   against the credential rate limiter (the password was correct — see
   Decisions) but is audited as `LOGIN_FAILED`.

6. **Authentication success.** Mint `sessionID`/`familyID`, generate the
   raw refresh token (`platform/refresh_token.Generator`) and the access
   token JWT (claims: `sub`=UserID, `sid`=SessionID). Neither depends on
   the database.

7. **Persist authentication state — single transaction.**
   1. `LockDeviceSlot(userID, deviceID)` — Postgres transaction-scoped
      advisory lock (`pg_advisory_xact_lock`), so concurrent logins for
      the same device serialize instead of racing.
   2. `FindActiveByUserAndDevice` under that lock.
   3. If an active session exists on this device: created within
      `DeviceGracePeriod` (default 5m, config
      `LOGIN_DEVICE_GRACE_PERIOD`) → supersede it
      (`RevokeSessionSuperseded`) and continue; older → leave it alone,
      return `ErrDeviceSessionActive` (409).
   4. Create the new session, create the refresh token row (family root:
      `ParentTokenID` nil).

8. **Publish audit event.** `LOGIN_SUCCESS` with userID/sessionID/IP/UA.
   A device-conflict rejection (step 7.3, older branch) is separately
   audited as `LOGIN_FAILED` after the transaction returns, since
   `account.ID` isn't resolved to a session at that point.

## Idempotency

This endpoint requires (not merely accepts) an `Idempotency-Key` header —
there are no deployed clients to keep compatible, so the stricter
contract is set from day one instead of retrofitted later (see
`middleware.Idempotency`'s `required` parameter to relax this).

Mechanism: `internal/platform/idempotency` (Redis, Lua GET-or-SET script,
mirroring `platform/authattempt`'s script pattern) +
`middleware/idempotency.go`. A request is hashed and its key claimed
atomically; the claim winner runs the handler and caches the full
response (status+body) for `IDEMPOTENCY_KEY_TTL` (default 10m); everyone
else either replays that response verbatim or polls briefly (bounded
well inside the 5s server timeout) and picks up the result once it
lands. A 5xx is never cached. The key is namespaced
`idem:<path>:<client-key>` so a client-supplied value can't collide with
unrelated Redis keys (e.g. `authattempt`'s own).

Unlike the rate limiter, a Redis outage here fails **open** (the request
runs unprotected) rather than closed — idempotency is a reliability
nicety, not a security control, so an outage in the safety net must not
become an availability outage for login itself.

Verified against real Redis, not just mocks: 25 and 30 truly concurrent
curl requests with an identical `Idempotency-Key` each produced exactly
one session and one distinct token pair, replayed to every caller.

## Device-Session Supersede / Concurrency

A second login for a device that already has an active session cannot
simply insert a new one: the database enforces one active session per
device (`uq_sessions_active_device`). The application layer handles this
gracefully — supersede within a grace period, reject past it — rather
than letting the raw constraint violation surface as a 500.

The grace period is a heuristic, not a security control — see Decisions
for why `device_id` can't be trusted as an identity proof, and why the
Idempotency-Key mechanism above is the actually-correct fix for the
retry case specifically, with the grace period remaining as the fallback
for clients that don't send a key.

The decide-then-act sequence (flow step 7) is serialized per `(user,
device)` by `LockDeviceSlot`, a Postgres advisory lock, so concurrent
logins for the same device can't race each other into the unique
constraint. `RevokeSession`'s `revoked_at` uses `clock_timestamp()`
rather than `NOW()`, since `NOW()` is fixed at transaction start: a
transaction that began earlier but committed later (because it queued
behind another transaction) could otherwise write a `revoked_at` earlier
than the row it was revoking, tripping
`sessions_revocation_check`. Verified live: 30 truly parallel requests
for one device, zero errors, exactly one active session.

## Decisions

- **Email canonicalization is per-domain, not universal.** See
  `docs/register.md` Decisions for the full rationale — the same
  `user.NormalizeEmail()` function backs both endpoints, so a user can
  authenticate with any equivalent variation of the address they
  registered a different one under (verified live: registering with
  `bayu.aditya+signup@gmail.com` and logging in with
  `bayuaditya@gmail.com` succeeds).

- **`device_id` is not an identity proof.** It's documented in the
  sessions migration as a client-generated opaque string — not a
  hardware fingerprint — so "same `device_id`, close in time" is a
  heuristic for "probably the same client retrying," not a security
  guarantee. Someone with the password and the `device_id` (e.g. an
  insider, or a credential leak) is indistinguishable from a genuine
  retry by this check alone. The Idempotency-Key mechanism is the actual
  fix for the retry case; the grace period is what's left for clients
  that don't use it.

- **Account-status rejection happens after password verification and is
  excluded from rate-limit counting** (flow step 5). Both are
  enumeration/self-DoS defenses: revealing lockout status only to a
  caller who already proved they know the password avoids leaking
  account existence, and not counting a correct-password rejection
  against the credential limiter avoids letting a known password be used
  to lock out its own legitimate owner.

- **Rate limiting fails closed** (a Redis error aborts the login);
  **idempotency fails open** (a Redis error runs the login unprotected).
  Deliberately different: one is a security control where "unprotected"
  means unlimited-rate brute force, the other is a reliability nicety
  where "unprotected" means at-least-once execution — plain old REST
  without the idempotency layer, not a new risk.

- **`CanLogin()`'s `LockedUntil` branch is presently unreachable from
  real data** — see Gaps.

- **Login does not gate on `EmailVerifiedAt`, and neither do refresh or
  logout.** An unverified account authenticates, refreshes, and logs out
  exactly like a verified one. This is deliberate, not an oversight: see
  `docs/email-verification.md` Decisions for the full rationale (gating
  would permanently lock out an account whose verification email
  bounced or was never opened, with no delivery mechanism in this repo
  robust enough to guarantee against that yet). `errs.ErrEmailNotVerified`
  is defined and mapped to `403`, but unreachable by design — verified
  live: an unverified account logged in, refreshed, and logged out
  without issue.

## Capabilities

- Email canonicalization (case/whitespace-insensitive, plus
  provider-specific rules — currently Gmail/Googlemail) shared with
  register via `user.NormalizeEmail()`.
- Two-tier Redis rate limiting (IP, credential+IP) via
  `platform/authattempt`.
- Constant-time dummy-hash verification against unknown accounts, so
  account existence isn't inferable from response timing.
- Account status gate (`CanLogin`).
- Device-identity input validation (non-empty `device_id`, known
  `device_type`).
- One active session per device, enforced at the database
  (`uq_sessions_active_device`) and handled gracefully at the
  application layer (supersede-within-grace-period / reject).
- Refresh token rotation family root creation (`ParentTokenID` nil) —
  consumed and extended by `/v1/auth/refresh`; see `docs/refresh.md`.
- Full audit trail: `LOGIN_SUCCESS`, `LOGIN_FAILED` (wrong password,
  locked account, device conflict — each with a distinguishing
  `Reason`).
- Idempotent retries via `Idempotency-Key` (see Idempotency above).

## Gaps

- **`CanLogin()`'s `LockedUntil` check can never actually trigger.** The
  `users` table has no `locked_until` or `failed_login_attempts` column
  at all (only `id`/`email`/`password_hash`/`status`/`email_verified_at`/
  `last_login_at`). The domain model (`user.RecordFailedLogin`,
  `user.LockedUntil`) is ahead of the schema. Wiring real lockout would
  mean two new columns + a migration, new repository methods, and login
  writing to them on success/failure — deliberately not done, since
  Redis-based IP/credential rate limiting already serves the
  anti-brute-force purpose this would duplicate, and no max-attempts/
  lock-duration policy has ever been established for it. Today the only
  reachable `CanLogin()==false` state is `Status` set directly by an
  operator (e.g. `UPDATE users SET status='LOCKED'` — verified live,
  correctly returns 403 `ACCOUNT_LOCKED` and is audited).

- **`UpdateLastLoginAt`** (`queries/user.sql`) is defined, generated by
  sqlc, and never called. The query's own comment says it should run
  post-transaction, not inside the login transaction, since it's not
  critical — that's still true; it's just not wired up. Small, safe
  follow-up: a best-effort call after flow step 8, matching how audit
  publishing is already best-effort.

- **Login does not know whether the device it's superseding actually
  belongs to the same physical device** making the "same `device_id`"
  claim (see Decisions). No additional signal (IP/UA match) gates the
  supersede path beyond the Idempotency-Key mechanism, which is the
  intended real fix rather than a heuristic tightening of the fallback.

## API Contract

**Request**

```
POST /v1/auth/login
Content-Type: application/json
Idempotency-Key: <client-generated string>   required

{
  "email":       string,  required
  "password":    string,  required
  "device_id":   string,  required, non-empty
  "device_name": string,  optional
  "device_type": string,  required, one of WEB | ANDROID | IOS
}
```

**Success — `200 OK`**

```json
{
  "data": {
    "access_token": "jwt",
    "refresh_token": "opaque-raw-token",
    "expires_in": 900
  }
}
```

A replayed response (`Idempotency-Key` reused within TTL, identical
body) returns the same status/body as the original, plus header
`Idempotency-Replayed: true`.

**Errors**

| Status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | malformed JSON, missing password, empty `device_id`, or unknown `device_type` |
| 400 | `INVALID_EMAIL` | email missing or not a valid address |
| 400 | `IDEMPOTENCY_KEY_REQUIRED` | `Idempotency-Key` header missing |
| 401 | `INVALID_CREDENTIALS` | unknown email or wrong password |
| 403 | `ACCOUNT_LOCKED` | `account.CanLogin()` is false |
| 409 | `DEVICE_SESSION_ALREADY_ACTIVE` | active session on this device, outside the grace period |
| 409 | `IDEMPOTENCY_KEY_CONFLICT` | same key, different request body |
| 409 | `IDEMPOTENCY_KEY_IN_PROGRESS` | same key still being processed by another in-flight request |
| 429 | `TOO_MANY_REQUEST` | IP or credential rate limit exceeded |
| 500 | `INTERNAL_ERROR` | unexpected failure |

## Tested Scenarios

Unit — `internal/app/auth/login/service_test.go`
(`go test ./internal/app/auth/login/... -race`):

- full success path: tokens returned, session+refresh token persisted
  correctly bound to each other, access token claims carry SessionID
- session `ExpiresAt` is set and outlives the refresh token TTL
- session records IP/UA/`device_id` from the request
- device-collision: recent session is superseded (revoked reason
  `SESSION_SUPERSEDED`), new session created
- device-collision: stale session is rejected (409), left untouched,
  audited
- a different `device_id` for the same user is unaffected by an
  existing session
- 16 truly concurrent goroutines logging in for the same device all
  succeed, end with exactly one active session (run under `-race`)
- malformed email, empty password, empty `device_id`, unknown
  `device_type` all rejected before touching any dependency
- locked account with the correct password → `ErrAccountLocked`, not
  counted against the credential rate limiter, audited
- unknown account → `ErrInvalidCredentials`, dummy hash verification ran
- wrong password → `ErrInvalidCredentials`, counted against the limiter
- IP-limited and credential-limited requests → `ErrTooManyRequests`
- transaction / access-token / device-session-lookup failures propagate
- audit trail: success case, failure case (counted against the
  limiter), and that success resets the credential limiter

Unit — `internal/domain/user/email_test.go`: email canonicalization
itself is tested once, at the shared function level, not duplicated per
endpoint — see `docs/register.md` Tested Scenarios.

Middleware unit — `internal/transport/http/middleware/idempotency_test.go`
(9 tests, run under `-race`): no-key rejection (and pass-through when
not required), first-request caches, 5xx not cached, replay without
re-invoking the handler, conflicting body rejected, still-in-progress
409 after timeout, a waiter picking up the winner's result mid-poll,
Redis-error degrade-to-unprotected, and 20 genuinely concurrent
identical requests executing the handler exactly once.

e2e — against the real docker-compose stack:

- register → login → refresh → logout, full lifecycle
- login without `Idempotency-Key` → 400
- login with empty `device_id` → 400; invalid `device_type` → 400
- 20 and 30 genuinely parallel curl logins for the same device, no
  Idempotency-Key: zero errors, exactly one active session, N-1
  correctly marked `SESSION_SUPERSEDED`
- 25 genuinely parallel curl logins with an identical Idempotency-Key:
  one distinct `refresh_token` across all responses, one session created
- same Idempotency-Key, different request body → 409
  `IDEMPOTENCY_KEY_CONFLICT`
- manually locking an account (`UPDATE users SET status='LOCKED'`) then
  logging in with the correct password → 403 `ACCOUNT_LOCKED`, audited
  as `LOGIN_FAILED` with reason "account is locked"
- registered with `bayu.aditya<n>+signup@gmail.com`, logged in
  successfully with `bayuaditya<n>@gmail.com` — a different variation of
  the same mailbox — proving login and register agree on identity
  through the shared `NormalizeEmail`
- audit trail `ip_address` and `session_id` confirmed populated across
  `LOGIN_SUCCESS` and `LOGIN_FAILED` rows
- registered an account, left it unverified, logged in successfully with
  it — confirming login is not gated on `EmailVerifiedAt` (see
  `docs/email-verification.md`)

## Related Files

```
internal/app/auth/login/service.go         use case
internal/app/auth/login/validator.go        input validation
internal/app/auth/login/policy.go           SecurityPolicy shape
internal/app/auth/login/event.go            LOGIN_SUCCESS / LOGIN_FAILED
internal/app/policy.go                      config -> SecurityPolicy
internal/domain/user/user.go                CanLogin, status lifecycle
internal/domain/user/email.go               NormalizeEmail, canonicalization rules
internal/domain/session/session.go          DeviceType.Valid(), RevokeReason
internal/domain/session/repository.go       LockDeviceSlot, FindActiveByUserAndDevice
internal/platform/idempotency/              Redis-backed idempotency Store
internal/transport/http/middleware/idempotency.go   Idempotency middleware
internal/platform/authattempt/              Redis-backed rate limiting
internal/platform/postgres/repository/session/repository.go   LockDeviceSlot,
                                             clock_timestamp() revoke
queries/session.sql                         LockDeviceSessionSlot,
                                             GetActiveSessionByUserAndDevice
internal/transport/http/handler/auth.go     HTTP handler
internal/transport/http/router.go           POST /v1/auth/login,
                                             Idempotency middleware mount
internal/platform/config/config.go          LOGIN_DEVICE_GRACE_PERIOD,
                                             IDEMPOTENCY_KEY_TTL
migrations/000004_create_sessions.up.sql    sessions table,
                                             uq_sessions_active_device
```
