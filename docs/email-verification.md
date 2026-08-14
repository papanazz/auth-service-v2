# Email Verification

`POST /v1/user/verify-email`
`POST /v1/user/verify-email/resend`

Confirms ownership of the email address supplied at registration.
Registration issues a token behind the scenes (see `docs/register.md`
Flow step 6); these two endpoints consume it and, if needed, reissue it.
Verification is **not** a login gate — see Decisions.

## Flow — Verify

`internal/app/user/verifyemail/service.go` — `Service.Handle`

1. **Locate the presented token.** Hash + `FindByHash`. Not found →
   `ErrInvalidVerificationToken` — the same code covers unknown, expired,
   and malformed alike (mirrors `ErrInvalidRefreshToken`'s stance; see
   `docs/refresh.md`).

2. **Reject an expired, unconsumed token.** A token consumed once but now
   past its own `ExpiresAt` is deliberately *not* rejected here — that
   case falls through to step 3 instead, so a previously successful
   verification stays confirmable independent of the token's clock.

3. **Already consumed → idempotent replay, not an error.** A second
   click on the same link, or a client retry, must not fail: the state
   the caller wants ("my email is verified") is already true. Loads the
   account by the token's `user_id` and returns its current
   `EmailVerifiedAt` — no write, no re-audit.

4. **Otherwise, verify.** Loads the account, calls the existing domain
   method `account.VerifyEmail(now)` (sets `EmailVerifiedAt`, transitions
   `PENDING`→`ACTIVE`), then in one transaction: `Consume(token.ID)` (a
   conditional `UPDATE ... WHERE consumed_at IS NULL`), then
   `MarkEmailVerified(...)`. See Idempotency and Concurrency for what
   happens when `Consume` loses its compare-and-swap.

5. **Publish audit event.** `EMAIL_VERIFIED`, `success=true`, with
   userID/email/IP/UA. Only on a genuine first verification — step 3's
   replay path does not re-publish.

## Flow — Resend

`internal/app/user/resendverification/service.go` — `Service.Handle`

Returns only `error`, and — deliberately — the same `nil` whether the
email is unregistered, already verified, or a real token was minted and
sent. See Decisions.

1. **Rate limit check.** One Redis-backed window per IP
   (`platform/authattempt.ResendVerificationIP`). Every attempt counts,
   not just ones that end up sending — the unknown-email and
   already-verified cases are exactly what an enumeration probe generates
   in bulk, same reasoning as register's limiter (`docs/register.md`).

2. **Resolve the account.** `FindByEmail` against the normalized address.
   Not found → return `nil` (no-op). Already verified
   (`EmailVerifiedAt != nil`) → return `nil` (no-op).

3. **Reuse the active token if its raw value is cached; otherwise mint a
   fresh one.** See Decisions for why re-delivering the identical token
   is the point of this endpoint, not an implementation detail.

4. **Publish the email and audit the send.** Both best-effort — a
   publish or audit failure does not fail the request; the token is
   already durably persisted at this point.

## Idempotency and Concurrency

**Verify's compare-and-swap.** `Consume` is a conditional
`UPDATE email_verification_tokens SET consumed_at = NOW() WHERE id = $1
AND consumed_at IS NULL`. Two concurrent verify calls for the identical
token both want the same outcome — unlike refresh, where a second use of
a token is treated as a theft signal and revokes the whole family (see
`docs/refresh.md`), here the CAS loser is not an attacker to punish, just
a second caller confirming what's already true. The loser's transaction
returns the unexported sentinel `errRaceLost`, caught outside the
transaction: it re-reads the winner's already-committed
`EmailVerifiedAt` and returns success from that, writing nothing and
publishing nothing itself. Verified at the unit level under `-race`
(`TestService_Handle_ConcurrentVerifyRaceStillSucceeds`).

**Resend's token cache is the one deliberate exception to "raw tokens
are never persisted."** Every other secret in this codebase
(`refresh_token`, session values) is stored durably only as a hash — the
raw value exists once, at issuance, and is never recoverable. Resend
breaks that on purpose: re-delivering the *identical* token on repeat
calls (rather than minting a new one, or silently no-op'ing while the
old one is still valid) was the explicit requirement, and a hash can't
be turned back into the value it came from. The raw token is cached in
Redis (`internal/platform/verification.RedisCache`, key
`verify:token:<token-id>`) with a TTL equal to the token's own
`ExpiresAt` — so the exposure window is bounded to exactly the token's
own validity period, not open-ended. A cache miss is not an error (see
`domain/verification/cache.go`'s doc comment): if the Postgres-durable
token is still valid but its Redis-cached raw value is gone (eviction,
Redis restart), resend mints and persists a brand new token rather than
failing the caller with nothing to send. The old, now-orphaned token row
is left alone to expire naturally — multiple simultaneously-valid tokens
for one user are harmless by this feature's design (unlike refresh
tokens, there is no family/rotation/replay-detection concept here at
all; see the migration's comment). Verified live: registering a user,
immediately calling resend, and confirming the exact same raw token
value was re-logged (`e2e-resend-*@example.com`, same
`5z2pzg170zylgFVr...` token both times).

## Decisions

- **Login, refresh, and logout do not check `EmailVerifiedAt`.** An
  unverified account can authenticate, rotate its refresh token, and log
  out exactly like a verified one — `errs.ErrEmailNotVerified` is
  defined but intentionally unreachable, same as it was before this
  feature existed (see `docs/login.md` Gaps, now upgraded from a passive
  gap to a stated decision now that a real verification flow exists to
  gate on). The trade-off: verification is a trust signal collected
  after account creation, not a precondition for using the account.
  Gating login on it would mean an account whose verification email
  bounced, or whose owner never clicks the link, is permanently locked
  out of authenticating at all — with no delivery mechanism in this repo
  yet (see Gaps), that risk is not worth taking on for a portfolio
  service. Verified live: registered an account, left it unverified,
  and successfully logged in, refreshed, and logged out with it.

- **Resend's response never reveals which case occurred.** Unregistered
  email, already-verified account, and a genuine send all return the
  identical `204 No Content`. Mirrors login's dummy-hash verification
  against unknown accounts (`docs/login.md` Capabilities) — the same
  class of leak, closed the same way: distinguishing these cases in the
  response would let this endpoint enumerate registered or verified
  accounts by email address alone.

- **Resend re-delivers the identical token while it's still valid,
  rather than minting a new one on every call or silently no-op'ing.**
  This was a deliberate choice among three options: (a) re-deliver the
  identical token via a bounded-TTL Redis cache of the raw value — what's
  built; (b) mint a fresh token every call, immediately invalidating the
  previous one; (c) no-op while a token is still active, forcing the
  caller to wait it out. (a) was chosen because it best matches how
  users actually behave — clicking an old email's link after requesting
  a new one should still work — without the accounting complexity of (b)
  (revoking the old token means tracking exactly one "the" active token
  per user) or the poor UX of (c) (a user who lost the first email has
  no way to get a working one before the TTL expires).

- **Verification tokens have no family/rotation/replay-detection
  concept, unlike refresh tokens** (`migrations/000009_...up.sql`
  comment). A second, third, or Nth concurrently-valid token for the
  same user is harmless — the worst a leaked-and-unused old token can do
  is verify an email that was going to get verified anyway. This is what
  makes the self-healing mint-on-cache-miss fallback (see Idempotency
  and Concurrency) safe to do unconditionally, with no cleanup of the
  orphaned row required.

- **`MarkEmailVerified` takes `status` as a parameter rather than
  computing the `PENDING`→`ACTIVE` transition in SQL.** The transition
  is a domain rule owned by `user.VerifyEmail()`
  (`internal/domain/user/user.go`), not persistence logic — the query
  layer stores whatever the domain decided, it doesn't decide anything
  itself. Same separation register already follows for `Status`
  (`docs/register.md` Flow step 5).

## Capabilities

- Single-use tokens: 43-byte random value (`crypto/rand` + base64,
  identical construction to `refresh_token.RandomGenerator`), SHA-256
  hashed for durable storage — the raw value is never persisted except
  in the bounded-TTL Redis cache described above.
- Configurable TTL (`EMAIL_VERIFICATION_TOKEN_TTL`, default 24h).
- Idempotent verify: a second confirmation of the same token, or two
  genuinely concurrent ones, both succeed — see Idempotency and
  Concurrency.
- Idempotent, enumeration-safe resend: identical `204` response
  regardless of account state; per-IP rate limiting
  (`RESEND_VERIFICATION_IP_LIMIT`/`_WINDOW`, default 3/10m), observable
  as `auth_rate_limit_rejections_total{limiter="auth:resend-verification:ip"}`
  — see `docs/metrics.md`.
- Email delivery is abstracted behind `domain/email.Publisher` — not
  implemented yet by design (see Gaps). Register and resend both depend
  on the interface only.
- Full audit trail: `EMAIL_VERIFIED` (verify success only, not the
  idempotent-replay path), `VERIFICATION_EMAIL_SENT` (resend, real sends
  only, not the no-op paths) — both also exported as
  `auth_events_total{type,success}`; see `docs/metrics.md`.
- Verifying activates a `PENDING` account (`user.VerifyEmail()`); has no
  effect on an already-`ACTIVE` account's status (register currently
  always creates `ACTIVE` accounts — see `docs/register.md` Decisions —
  so this branch is not reachable from today's register flow, only from
  direct domain use, consistent with how `docs/register.md` already
  flags `PENDING` as schema-supported-but-unused).

## Gaps

- **`platform/email.LogPublisher` is a stub, not a real mailer.** It
  logs the verification email — including the raw token — as a
  structured log line instead of sending anything (`[email]
  verification email not sent — no provider configured`). This was
  explicit scope for this pass ("abstract it, we not implement sending
  email feature yet"): `domain/email.Publisher` is the seam a real
  provider (SES, Postgres-backed outbox + worker, etc.) plugs into
  later. **Logging the raw token is fine for local development, not
  acceptable for production** — application logs are a much wider-access
  surface than an email inbox. Swapping in a real publisher removes this
  exposure entirely; it's flagged here so it isn't mistaken for a
  finished feature.
- **No cap on how many concurrently-valid tokens a user can accumulate.**
  Each cache-miss resend mints a new row rather than invalidating old
  ones (see Idempotency and Concurrency). Harmless per the no-replay-
  detection design, but an unbounded number of rows per user is possible
  under pathological repeated cache eviction. Not worth guarding against
  today — old rows are cheap and expire on their own — but the operative
  assumption is documented here in case token-table growth ever becomes
  a real concern.
- **No endpoint surfaces verification status to the caller directly** —
  a client has to infer it from the register/login response bodies,
  neither of which currently include `email_verified_at`. Small,
  low-priority follow-up if a client needs to show a "please verify"
  banner without a dedicated `/me` endpoint.

## API Contract

### Verify

**Request**

```
POST /v1/user/verify-email
Content-Type: application/json

{
  "token": string  // required, the raw token from the verification email
}
```

**Success — `200 OK`**

```json
{
  "data": {
    "email": "user@example.com",
    "verified_at": "2026-08-14T11:38:57.278Z"
  }
}
```

Calling this endpoint twice with the same (now-consumed) token, or many
times concurrently with the same token, still returns `200` every time
with the same `verified_at` — see Idempotency and Concurrency above.

**Errors**

| Status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | malformed JSON body |
| 400 | `INVALID_VERIFICATION_TOKEN` | unknown, expired-and-unconsumed, or malformed token — a client cannot distinguish these |
| 500 | `INTERNAL_ERROR` | unexpected failure |

No authentication required — the token itself is the credential.

### Resend

**Request**

```
POST /v1/user/verify-email/resend
Content-Type: application/json

{
  "email": string  // required
}
```

**Success — `204 No Content`**

Empty body, unconditionally — see Decisions for why the response cannot
be used to distinguish "sent" from "no-op."

**Errors**

| Status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | malformed JSON body |
| 429 | `TOO_MANY_REQUEST` | per-IP rate limit exceeded |
| 500 | `INTERNAL_ERROR` | unexpected failure |

No authentication required. Note there is no `INVALID_EMAIL` response:
an unparseable address is simply normalized and treated as unknown (a
no-op `204`), the same enumeration-safety reasoning as every other case
this endpoint hides.

## Tested Scenarios

Unit — `internal/app/user/verifyemail/service_test.go`
(`go test ./internal/app/user/verifyemail/... -race`):

- success: token consumed, account marked verified, `EMAIL_VERIFIED`
  audited with the correct user ID/email/IP/UA
- a `PENDING` account transitions to `ACTIVE` on verification
- an already-consumed token replays successfully with the original
  `verified_at`, without a second write or a second audit event
- 2-way CAS race: the `Consume` loser still returns `200` with the
  winner's actually-committed `verified_at`, and does not write
  (run under `-race`)
- unknown token, expired-and-unconsumed token, token/user lookup
  failures, transaction failure, mark-verified failure — all
  rejected/propagated correctly

Unit — `internal/app/user/resendverification/service_test.go`
(`go test ./internal/app/user/resendverification/... -race`):

- unknown email and already-verified account are both silent no-ops (no
  token created, no email published, no audit event) — except the rate
  limit counter, which still advances
- mints and sends a fresh token for an unverified account with no active
  token; `VERIFICATION_EMAIL_SENT` audited
- the centerpiece: an active token whose raw value is cached is reused
  verbatim — no new token row created, the cached raw value is what gets
  published
- self-healing: an active token whose raw value is *not* cached gets a
  freshly minted replacement, published with the new raw value
- rejects a request over the IP limit; propagates a rate-limiter
  failure; counts an attempt even on a no-op resolution
- propagates an unexpected account-lookup failure

e2e — against the real docker-compose stack:

- register → verify-email with the correct token → `200`, account
  becomes `ACTIVE` with `email_verified_at` populated, token row's
  `consumed_at` set, audit trail `USER_REGISTERED` then `EMAIL_VERIFIED`
  in order
- verify-email again with the same now-consumed token → `200`, identical
  `verified_at`, exactly one `EMAIL_VERIFIED` audit row total (no
  re-audit on replay)
- verify-email with a garbage/unknown token → `400`
  `INVALID_VERIFICATION_TOKEN`
- register → immediately call resend → the exact same raw token value
  is re-logged by `LogPublisher`, proving literal reuse rather than a
  fresh mint
- resend rate limiting: 3 requests succeed (`204`), the 4th returns
  `429`, confirmed the limit key is per-IP (shared across different
  target emails from the same client)
- unknown-email resend → `204`, no token log line emitted
- already-verified-account resend → `204`, no token log line emitted
- unverified account: login, refresh, and logout all succeed normally —
  confirms verification is not a gate on any of the three, per Decisions
  above

## Related Files

```
internal/app/user/verifyemail/service.go            verify use case
internal/app/user/verifyemail/event.go               EMAIL_VERIFIED constructor
internal/app/user/resendverification/service.go     resend use case
internal/app/user/resendverification/policy.go      SecurityPolicy
internal/app/user/resendverification/event.go       VERIFICATION_EMAIL_SENT constructor
internal/app/policy.go                                config -> SecurityPolicy
internal/domain/verification/token.go                Token entity, Expired()/Consumed()
internal/domain/verification/repository.go           Repository interface
internal/domain/verification/cache.go                Cache interface (the raw-token exception)
internal/domain/verification/generator.go            Generator interface
internal/domain/verification/hasher.go               Hasher interface
internal/domain/email/publisher.go                    Publisher interface, VerificationEmail
internal/domain/user/user.go                          VerifyEmail(), status lifecycle
internal/platform/verification/                       generator/hasher/cache implementations
internal/platform/postgres/repository/verification/  Postgres Repository
internal/platform/email/log_publisher.go              LogPublisher stub
internal/platform/authattempt/key.go                  ResendVerificationIP
internal/transport/http/handler/verifyemail.go        HTTP handler
internal/transport/http/handler/resendverification.go HTTP handler
internal/transport/http/router.go                     POST /v1/user/verify-email(/resend)
internal/platform/config/config.go                    EMAIL_VERIFICATION_TOKEN_TTL,
                                                        RESEND_VERIFICATION_IP_LIMIT/WINDOW
migrations/000009_create_email_verification_tokens.up.sql   token table
queries/verification.sql                               hand-written SQL
```
