# Register

`POST /v1/user/register`

Creates a new identity. Does not authenticate the caller — register and
login are separate steps; this endpoint returns no tokens.

## Flow

`internal/app/user/register/service.go` — `RegisterService.Handle`

1. **Normalize and validate input.** `user.NormalizeEmail()` lowercases
   and trims the address, and — for a known provider (currently Gmail) —
   collapses dots and a `+tag` in the local part to their canonical form.
   Shared with login, so both endpoints agree on what "the same email"
   means; see Decisions. `Validate()` (`validator.go`) then rejects
   anything `net/mail` can't parse.

2. **Rate limit check.** One Redis-backed window, per IP
   (`platform/authattempt`). Every attempt counts toward the limit, not
   just failures — a validation failure or a duplicate-email attempt
   still increments the counter, since both are exactly what an
   account-creation or email-enumeration bot generates in bulk. The
   counter advances immediately after this check, before anything else
   runs.

3. **Enforce password policy.** `platform/password.Policy`: minimum 8
   characters, at least one uppercase, one lowercase, one digit.

4. **Reject a duplicate account.** `FindByEmail` against the normalized
   address. Racy against a concurrent registration for the same
   email — the database's `UNIQUE` constraint on `users.email` is the
   real guarantee; this check exists to turn the common case into a
   clean `USER_ALREADY_EXISTS` instead of a raw constraint-violation
   error reaching the client.

5. **Hash the password and persist the account.** Argon2id
   (`platform/password/argon2id.go`): 64 MiB memory, 3 iterations, 2
   threads, 16-byte salt, 32-byte key. The account is built via
   `user.New()`, then `Status` is immediately forced to `ACTIVE` — see
   Decisions.

6. **Publish audit event.** `USER_REGISTERED`, `success=true`, with the
   account's email/IP/user agent. Best-effort (errors are swallowed) —
   an audit outage must not fail a registration that already succeeded.
   Only the success path is audited; see Gaps.

## Decisions

- **Email canonicalization is per-domain, not universal.** Gmail
  documents that dots in the local part are insignificant and that a
  `+tag` is discarded on delivery, so `bayu.aditya@gmail.com`,
  `bayuaditya@gmail.com`, and `bayuaditya+work@gmail.com` are the same
  mailbox and are collapsed to one stored value
  (`internal/domain/user/email.go`). This is deliberately *not* applied
  to every domain: for most providers — and especially corporate domains
  using a `first.last@company.com` convention — a dot is a real,
  meaningful separator between two different mailboxes, not decoration.
  Applying Gmail's rule universally would be a correctness bug (silently
  merging distinct accounts), not a hardening. The rule table is keyed
  by domain and documented as extend-by-verification: a new provider
  only gets an entry once its own documentation confirms the
  equivalence, not by assuming it matches Gmail's behavior.

- **Accounts are created `ACTIVE`, not `PENDING`.** `user.New()` defaults
  to `PENDING`, and the domain model is clearly shaped for an email
  verification flow (`EmailVerifiedAt`, `VerifyEmail()`, the `PENDING`
  status itself). There is no verification token, no delivery mechanism,
  and no endpoint to complete verification — shipping `PENDING` today
  would permanently strand every new account with no way to ever reach
  `ACTIVE`. `service.go` overrides the status explicitly, with a comment
  pointing here. See Gaps.

- **Rate limiting counts every attempt, not just failures**, unlike
  login's credential-based limiter (which only counts wrong-password
  guesses). The threat register defends against is volume from one
  source — mass account creation and email-enumeration probing both
  generate many attempts regardless of whether any individual one
  succeeds — so the counter has to advance unconditionally to cap it.

- **Duplicate-email detection is a pre-check, not a caught constraint
  violation.** Losing the race surfaces as a 500 on a call the client
  will typically retry with a different email anyway, not a silent
  security or data-integrity issue. See Gaps.

- **`register.Command` carries `IPAddress`/`UserAgent`**, filled by the
  HTTP handler from `r.RemoteAddr` / `r.UserAgent()`, the same pattern
  `handler/auth.go` uses — so the audit event and the rate limiter both
  see the same client context login's do.

## Capabilities

- Case/whitespace-insensitive email normalization, plus provider-specific
  canonicalization (currently Gmail/Googlemail: dots and `+tag` in the
  local part collapse to one identity) — shared with login via
  `user.NormalizeEmail()`, extensible to other providers by adding a
  verified rule to the table in `internal/domain/user/email.go`.
- Per-IP rate limiting on registration attempts
  (`REGISTER_IP_LIMIT`/`REGISTER_IP_WINDOW`).
- Password policy enforcement (`platform/password.Policy`).
- Argon2id password hashing — the raw password never reaches the
  repository or the database.
- Audit trail entry (`USER_REGISTERED`) with email, IP, and user agent.
- User enumeration is not specifically defended here the way login
  defends it (dummy-hash verification on unknown accounts): a duplicate
  email returns `USER_ALREADY_EXISTS`. This is an intentional
  trade-off — the endpoint's job is to tell the caller whether an email
  is already taken — mitigated at the volume level by the rate limiter
  above rather than by hiding the signal itself.

## Gaps

- **Email verification is unbuilt.** `user.New()` / `VerifyEmail()` /
  `EmailVerifiedAt` exist in the domain model; nothing in this service
  uses them beyond the status override. Building this out requires: a
  verification token + TTL, an email delivery mechanism (none exists in
  this repo), a verify endpoint, and login gating on `EmailVerifiedAt`.
  The natural next capability if this project needs to look more
  production-shaped.

- **Failure-path auditing is incomplete.** Only a successful registration
  is published. A duplicate-email attempt is a real security signal
  (account enumeration) but `audit.EventType` has no failure constant
  for registration the way `EventLoginFailed` exists for login.

- **The duplicate-email pre-check's race loses to a 500** instead of a
  mapped 409/`USER_ALREADY_EXISTS`. Low priority: the constraint still
  protects data integrity; this only affects the error shape returned to
  the loser of a true concurrent double-submit of the same email.

## API Contract

**Request**

```
POST /v1/user/register
Content-Type: application/json

{
  "email":    string,  required, valid RFC 5322 address
  "password": string,  required, >=8 chars, upper+lower+digit
}
```

**Success — `201 Created`**

```json
{
  "data": {
    "id": "uuid",
    "email": "normalized@example.com"
  }
}
```

**Errors**

| Status | Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | malformed JSON body |
| 400 | `INVALID_EMAIL` | email missing or not a valid address |
| 400 | `WEAK_PASSWORD` | password fails the policy |
| 409 | `USER_ALREADY_EXISTS` | email already registered |
| 429 | `TOO_MANY_REQUEST` | IP rate limit exceeded |
| 500 | `INTERNAL_ERROR` | unexpected failure |

No authentication required.

## Tested Scenarios

Unit — `internal/app/user/register/service_test.go`
(`go test ./internal/app/user/register/... -race`):

- registers a new account
- normalizes email casing and surrounding whitespace
- rejects a malformed email
- rejects a password the policy refuses
- rejects an email that already exists
- propagates an unexpected lookup, hashing, or create failure
- persists the normalized account with a hashed password, `ACTIVE`
  status, no `EmailVerifiedAt`, and an ID matching the returned result
- publishes `USER_REGISTERED` with the correct user ID, email, IP, and
  user agent on success; does not publish anything on failure
- rejects a request over the IP limit; propagates a rate-limiter failure
- counts an attempt toward the limit even when it goes on to fail
  validation (e.g. duplicate email)

Unit — `internal/platform/authattempt/key_test.go`: two connections from
the same client on different ephemeral ports produce the same rate-limit
key for `RegisterIP`/`LoginIP`/`LoginCredential`.

Unit — `internal/domain/user/email_test.go`
(`go test ./internal/domain/user/... -race`):

- lowercases and trims regardless of domain
- Gmail: dots in the local part are insignificant, individually and
  combined with a `+tag`; a dot inside the `+tag` doesn't leak into the
  canonicalized local part
- `googlemail.com` aliases to `gmail.com` under the same rules
- a non-Gmail domain keeps both its dots and its `+tag` untouched — no
  documented equivalence assumed
- malformed input (no `@`) and the empty string pass through safely
- nine different ways of writing the same Gmail mailbox all converge to
  one canonical value
- `NormalizeEmail` is idempotent (applying it to its own output is a
  no-op) — matters because register normalizes on write and `user.New`
  normalizes again inside `Create`

e2e — against the real docker-compose stack:

- `POST /v1/user/register` with a fresh email → 201, well-formed body
- re-registering the same email → 409 `USER_ALREADY_EXISTS`
- registered `bayu.aditya<n>+signup@gmail.com`; stored as
  `bayuaditya<n>@gmail.com`; a plain-variant and a `+tag`-variant
  re-registration attempt of the same mailbox both → 409
  `USER_ALREADY_EXISTS`
- registered with one Gmail variant, logged in successfully with a
  different variant of the same mailbox → 200, proving register and
  login agree on identity through the shared `NormalizeEmail`
- `first.last@company.com` on a non-Gmail domain registers with its dot
  intact (unaffected by the Gmail rule)
- audit row created with `type=USER_REGISTERED`, `success=true`, correct
  email, IP, and user agent
- rate limiting verified live at a temporarily lowered limit (3 per 30s):
  first 3 requests succeed, the next 2 return 429, and the limit resets
  once the window expires
- full lifecycle sanity: register → login → refresh → logout all succeed
  end-to-end

## Related Files

```
internal/app/user/register/service.go              use case
internal/app/user/register/validator.go             email format check
internal/app/user/register/event.go                 USER_REGISTERED constructor
internal/app/user/register/policy.go                SecurityPolicy
internal/app/policy.go                               config -> SecurityPolicy
internal/domain/user/user.go                         User entity, status lifecycle
internal/domain/user/email.go                        NormalizeEmail, canonicalization rules
internal/domain/user/repository.go                   Repository interface
internal/domain/password/                            Hasher / Policy interfaces
internal/platform/password/                          Argon2id, Policy implementations
internal/platform/authattempt/                        Redis-backed rate limiting
internal/platform/postgres/repository/user/           Postgres Repository
internal/platform/postgres/repository/audit/          Postgres Publisher
internal/transport/http/handler/user.go               HTTP handler
internal/transport/http/router.go                     POST /v1/user/register
internal/platform/config/config.go                    REGISTER_IP_LIMIT/WINDOW
migrations/000003_create_users.up.sql                 users table
migrations/000007_align_user_status_enum.up.sql       status enum
```
