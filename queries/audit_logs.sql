-- =====================================================
-- Create Authentication Event
-- =====================================================

-- name: CreateAuthenticationEvent :one

INSERT INTO authentication_events
(
    id,

    type,

    user_id,

    email,

    ip_address,

    user_agent,

    success,

    reason,

    metadata,

    created_at
)

VALUES
(
    $1,

    $2,

    $3,

    $4,

    $5,

    $6,

    $7,

    $8,

    $9,

    $10
)

RETURNING *;