-- name: CreateAuditLog :one

INSERT INTO authentication_events
(
    id,
    event_type,
    user_id,
    email,
    ip_address,
    user_agent,
    success,
    failure_reason,
    metadata
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
    $9
)
RETURNING *;