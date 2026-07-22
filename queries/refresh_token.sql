-- name: CreateRefreshToken :one

INSERT INTO refresh_tokens
(
    id,
    session_id,
    token_hash,
    expires_at
)
VALUES
(
    $1,
    $2,
    $3,
    $4
)
RETURNING *;



-- name: GetRefreshTokenByHash :one

SELECT *
FROM refresh_tokens
WHERE token_hash = $1
AND revoked_at IS NULL
LIMIT 1;



-- name: RevokeRefreshToken :exec

UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE id = $1;