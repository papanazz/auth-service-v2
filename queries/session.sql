-- =====================================================
-- Create Session
-- =====================================================


-- name: CreateSession :one

INSERT INTO sessions (

    id,

    user_id,

    device_id,

    device_name,

    device_type,

    user_agent,

    ip_address,

    last_used_at,

    expires_at

)

VALUES (

    $1,

    $2,

    $3,

    $4,

    $5,

    $6,

    $7,

    $8,

    $9

)

RETURNING *;



-- =====================================================
-- Find Session By ID
-- =====================================================


-- name: GetSessionByID :one

SELECT *

FROM sessions

WHERE id = $1

LIMIT 1;



-- =====================================================
-- Find Active Session
-- =====================================================


-- name: GetActiveSessionByID :one

SELECT *

FROM sessions

WHERE id = $1

AND revoked_at IS NULL

LIMIT 1;



-- =====================================================
-- Lock Device Session Slot
-- =====================================================
--
-- A device may hold at most one active session (see
-- uq_sessions_active_device). This takes a transaction-scoped advisory lock
-- keyed by (user_id, device_id) so concurrent logins for the same device
-- serialize on the decide-then-act sequence (supersede vs. reject) instead
-- of racing each other into the unique constraint. Released automatically
-- at transaction end — no matching unlock call is needed.
-- =====================================================


-- name: LockDeviceSessionSlot :exec

SELECT pg_advisory_xact_lock(hashtextextended($1, 0));



-- =====================================================
-- Find Active Session By User And Device
-- =====================================================
--
-- Backs the partial unique index uq_sessions_active_device: a user may
-- have at most one active session per device_id. Used by login to detect
-- a device already holding an active session before creating a new one.
-- =====================================================


-- name: GetActiveSessionByUserAndDevice :one

SELECT *

FROM sessions

WHERE user_id = $1

AND device_id = $2

AND revoked_at IS NULL

LIMIT 1;



-- =====================================================
-- Revoke Session
-- =====================================================


-- name: RevokeSession :exec
--
-- revoked_at uses clock_timestamp(), not NOW(): NOW() is fixed at
-- transaction start, but a session can be revoked by a transaction that
-- began before — and, thanks to LockDeviceSessionSlot, committed after — the
-- transaction that created it. With NOW() that ordering can write a
-- revoked_at earlier than the row's created_at and trip
-- sessions_revocation_check. clock_timestamp() reflects real execution time,
-- which the lock guarantees is after the creating transaction committed.

UPDATE sessions

SET

    revoked_at = clock_timestamp(),

    revoked_reason = $2,

    updated_at = NOW()

WHERE id = $1

AND revoked_at IS NULL;



-- =====================================================
-- Update Last Used
-- =====================================================


-- name: UpdateSessionLastUsedAt :exec

UPDATE sessions

SET

    last_used_at = NOW(),

    updated_at = NOW()

WHERE id = $1;

-- name: UpdateSessionLastRefreshedAt :exec

UPDATE sessions

SET

	last_refreshed_at = NOW(),

	updated_at = NOW()

WHERE id = $1;