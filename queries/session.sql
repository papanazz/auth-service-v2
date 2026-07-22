-- name: CreateSession :one

INSERT INTO sessions
(
    id,
    user_id,
    device_id,
    device_name,
    device_type,
    user_agent,
    ip_address
)
VALUES
(
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7
)
RETURNING *;



-- name: RevokeSession :exec

UPDATE sessions
SET revoked_at = NOW()
WHERE id = $1;