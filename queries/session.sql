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
-- Revoke Session
-- =====================================================


-- name: RevokeSession :exec

UPDATE sessions

SET

    revoked_at = NOW(),

    updated_at = NOW()

WHERE id = $1;



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