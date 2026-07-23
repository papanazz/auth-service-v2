-- =====================================================
-- Create Refresh Token
-- =====================================================


-- name: CreateRefreshToken :one

INSERT INTO refresh_tokens (

    id,

    session_id,

    family_id,

    parent_token_id,

    token_hash,

    expires_at

)

VALUES (

    $1,

    $2,

    $3,

    $4,

    $5,

    $6

)

RETURNING *;



-- =====================================================
-- Find Token By Hash
-- =====================================================


-- name: GetRefreshTokenByHash :one

SELECT *

FROM refresh_tokens

WHERE token_hash = $1;



-- =====================================================
-- Consume Token
-- =====================================================
--
-- Atomic operation.
--
-- Prevents double refresh.
--
-- =====================================================


-- name: ConsumeRefreshToken :execrows

UPDATE refresh_tokens

SET consumed_at = NOW()

WHERE id = $1

AND consumed_at IS NULL;



-- =====================================================
-- Revoke Family
-- =====================================================


-- name: RevokeRefreshTokenFamily :exec

UPDATE refresh_tokens

SET

revoked_at = NOW(),

revoked_reason = $2

WHERE family_id = $1

AND revoked_at IS NULL;