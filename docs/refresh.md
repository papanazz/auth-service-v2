# Refresh

`POST /v1/auth/refresh`

Exchanges a refresh token for a new access token, rotating the refresh
token itself in the same call. Does not require an `Idempotency-Key` —
see Idempotency below for why login and refresh made opposite choices.

## Flow

`internal/app/auth/refresh/service.go` — `Service.Handle`

1. **Locate the presented token.** Hash the raw token, look it up by
   hash (raw tokens are never stored — see `docs/login.md` Decisions on
   the same point for login). Not found → `ErrInvalidRefreshToken`,
   audited.

2. **Resolve its owning session.** `FindByID(current.SessionID)`. Not
   found → `ErrInvalidRefreshToken`, audited. Only the session ID is
   known at this point — see Decisions for why that distinction matters
   to the audit trail.

3. **Detect replay.** `current.ConsumedAt != nil` means this exact token
   has already been exchanged once — rotation makes every token
   single-use, so a second use can only mean two parties hold the same
   one. The whole family is revoked (`RevokeReasonReplay`), not just
   this token: every descendant of a compromised token is equally
   suspect. This is a fast path, not the real guard — see step 6.

4. **Reject a revoked or expired token or session.** Both `current` (the
   token) and `sessionData` (its session) are checked for
   `RevokedAt`/`ExpiresAt`. Either failing returns the same
   `ErrInvalidRefreshToken` a client can't distinguish from "never
   existed" — a revoked/expired token carries no more information to a
   caller than an unknown one does.

5. **Mint the replacement token.** New raw token + hash, chained to the
   presented token (`ParentTokenID`) within the same `FamilyID`. Not yet
   persisted.

6. **Persist the rotation atomically.** Single transaction:
   `Consume(current.ID)` — a conditional `UPDATE` (`consumed_at IS
   NULL`) — then create the replacement, then `UpdateLastRefreshedAt` on
   the session. `Consume` is the actual concurrency guard: it's a
   compare-and-swap, so exactly one concurrent caller for the same token
   wins it; every loser gets `!consumed` and is funneled into the same
   replay handling as step 3 (family revoked, `TOKEN_REUSE_DETECTED`
   audited). Verified under `-race` with 32 concurrent callers
   presenting the identical token: exactly 1 success, 31 replays,
   exactly 1 replacement token issued.

7. **Mint the new access token.** Claims: `sub`=UserID, `sid`=SessionID
   — see Decisions for why `sid` must always be populated here.

8. **Publish audit event.** `TOKEN_REFRESH`, `success=true`, with
   userID/sessionID/IP/UA.

## Idempotency

Refresh does not use the Idempotency-Key mechanism login uses (see
`docs/login.md`). It doesn't need to: rotation is already
self-idempotent-adjacent by construction — `Consume`'s compare-and-swap
means a retried request with the same (now-consumed) token is
indistinguishable from an attacker replaying it, and is correctly
rejected either way. A genuine client retry after a dropped connection
gets a replay error, not a duplicate side effect — the client's real fix
is to retry with the *new* token if it received one, or treat the replay
as "the previous attempt actually succeeded, tokens were issued, I just
didn't see the response." This is a materially different retry story
than login's (which mints a brand-new session per attempt and has no
CAS-guarded resource to fall back on).

## Decisions

- **Refresh does not gate on `EmailVerifiedAt`.** An unverified
  account's refresh token rotates exactly like a verified one's —
  deliberate, same reasoning as login and logout; see
  `docs/email-verification.md` Decisions. Verified live: an unverified
  account's refresh token was exchanged successfully.

- **No rate limiting on this endpoint, unlike login.** Deliberate, not
  an oversight: login's rate limiting defends against password guessing,
  which is feasible because passwords are low-entropy and human-chosen.
  Refresh tokens are 256-bit random values
  (`platform/refresh_token.Generator`) — brute-forcing one is not a
  practical attack, so the rate limiter's purpose doesn't transfer.
  Resource exhaustion / DoS protection is a different, unaddressed
  concern — see Gaps.

- **`current.ConsumedAt` is checked before entering the transaction**
  (flow step 3) purely as a fast path for an obviously-already-spent
  token. The real correctness guarantee is `Consume`'s CAS inside the
  transaction (step 6) — removing the step-3 check would not
  reintroduce a race, only add unnecessary transaction overhead for the
  common slow-replay case.

- **`sessions.Repository.FindByID` is used here, not
  `FindActiveByID`.** `FindActiveByID` only filters on `revoked_at` at
  the SQL level — expiry still has to be checked in Go regardless of
  which one is called (flow step 4) — so switching would not remove a
  manual check, only change which error path a revoked session takes on
  the way to the same `ErrInvalidRefreshToken`. Left as `FindByID`
  deliberately; not a gap.

- **Access token claims always include `SessionID`.** An earlier version
  omitted it, so `sid` came out as the zero UUID after every refresh —
  silently breaking any future use of `sid` to identify a session
  directly from an access token (e.g. a Bearer-based logout or
  authorization scheme, discussed but not built). Regression test:
  `TestService_Handle_AccessTokenCarriesSessionID`.

- **`refreshFailedEvent` takes `userID` and `sessionID` as two
  independent optional parameters, not one overloaded slot**, because
  the two resolve independently and can fail independently: an unknown
  token hash yields neither; a token whose owning session lookup fails
  yields the session ID but never the user ID — the lookup that would
  have supplied it is exactly what failed. An earlier version passed the
  session ID into a slot the function signature called `userID`; because
  both are `uuid.UUID`, it compiled silently and would have written the
  wrong identifier into the audit trail's `user_id` column for every
  refresh whose session lookup failed. Regression test:
  `TestService_Handle_SessionLookupFailureDoesNotMisattributeUserID`.

## Capabilities

- Refresh token rotation: each exchange is single-use, chained via
  `ParentTokenID` inside a `FamilyID`.
- Replay detection with full-family revocation, verified as
  race-correct under concurrent identical requests, not just sequential
  ones.
- Full audit trail: `TOKEN_REFRESH` (success), `TOKEN_REFRESH_FAILED`
  (unknown/expired/revoked token or session), `TOKEN_REUSE_DETECTED`
  (replay) — each carrying user ID, session ID, IP, and user agent.
  `TOKEN_REUSE_DETECTED` is also its own alertable
  `auth_events_total{type="TOKEN_REUSE_DETECTED"}` series, distinct from
  the routine `TOKEN_REFRESH_FAILED` count even though both return the
  same `401` — see `docs/metrics.md`, which this endpoint's replay
  handling was the main motivation for.

## Gaps

- **No rate limiting or abuse protection on this endpoint** (see
  Decisions for why brute-forcing a token isn't the relevant threat). A
  resource-exhaustion angle (many refresh calls per second from one
  source) is unaddressed and would need its own justification and
  policy if it becomes a concern — not the same problem login's rate
  limiter solves, so not solved by reusing it.

## API Contract

**Request**

```
POST /v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": string  // required, raw token as issued by login or a previous refresh
}
```

**Success — `200 OK`**

```json
{
  "data": {
    "access_token": "jwt, sid = the session's real ID",
    "refresh_token": "new raw token — the presented one is now consumed and unusable",
    "expires_in": 900
  }
}
```

**Errors**

| Status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | malformed JSON body |
| 401 | `AUTH_INVALID_REFRESH_TOKEN` | unknown, expired, or revoked token or session — a client cannot distinguish these from each other |
| 401 | `AUTH_REFRESH_TOKEN_REPLAY` | a consumed token was presented again; the entire token family has been revoked as a side effect — every token derived from it, including ones not yet consumed, stops working |
| 500 | `INTERNAL_ERROR` | unexpected failure |

## Tested Scenarios

Unit — `internal/app/auth/refresh/service_test.go`
(`go test ./internal/app/auth/refresh/... -race`):

- full success path: new token issued, chained to the correct parent and
  family, session's `last_refreshed_at` updated
- access token claims carry the real SessionID
- a session with a real (non-zero) future expiry is accepted
- a session with a zero `ExpiresAt` is rejected as expired, not accepted
  (regression test for a prior outage where every refresh against a
  login-created session looked expired)
- unknown token, gone session, expired token, revoked token, revoked
  session, transaction failure, access-token generation failure — all
  rejected/propagated correctly
- presenting an already-consumed token revokes the whole family
- 32 concurrent goroutines presenting the identical token: exactly 1
  success, 31 replay rejections, exactly 1 replacement token created
  (run under `-race`)
- audit events carry the correct user ID, session ID, IP, and user agent
- a failed session lookup does not misattribute the session ID as the
  user ID in the audit trail (regression test)

e2e — against the real docker-compose stack:

- register → login → refresh → logout, full lifecycle
- refreshing, then replaying the now-consumed token → 401 replay,
  correctly audited with both `user_id` and `session_id` populated
- `authentication_events.session_id` confirmed populated for
  `LOGIN_SUCCESS`, `TOKEN_REFRESH`, and `LOGOUT` rows; correctly `NULL`
  for `USER_REGISTERED`
- `authentication_events.ip_address` / `user_agent` confirmed populated
  for a `TOKEN_REFRESH` row

## Related Files

```
internal/app/auth/refresh/service.go        use case
internal/app/auth/refresh/event.go          TOKEN_REFRESH / _FAILED /
                                             TOKEN_REUSE_DETECTED
internal/domain/refresh_token/              Token entity, Repository,
                                             Generator, Hasher interfaces
internal/domain/session/repository.go       FindByID, UpdateLastRefreshedAt
internal/domain/audit/event.go              Event.SessionID
internal/platform/postgres/repository/refresh_token/   Postgres Repository
internal/platform/postgres/repository/audit/mapper.go  SessionID mapping
internal/transport/http/handler/refresh.go  HTTP handler
internal/transport/http/router.go           POST /v1/auth/refresh
queries/refresh_token.sql                   Consume, RevokeFamily, etc.
queries/audit_logs.sql                      CreateAuthenticationEvent
migrations/000005_create_refresh_tokens.up.sql       refresh_tokens table
migrations/000006_create_authentication_events.up.sql   authentication_events table
migrations/000008_add_session_id_to_authentication_events.up.sql   session_id column
```
