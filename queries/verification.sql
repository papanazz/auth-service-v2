-- =====================================================
-- Create Verification Token
-- =====================================================


-- name: CreateVerificationToken :one

INSERT INTO email_verification_tokens (

    id,

    user_id,

    token_hash,

    expires_at

)

VALUES (

    $1,

    $2,

    $3,

    $4

)

RETURNING *;



-- =====================================================
-- Find Token By Hash
-- =====================================================


-- name: GetVerificationTokenByHash :one

SELECT *

FROM email_verification_tokens

WHERE token_hash = $1;



-- =====================================================
-- Find Active Token For User
--
-- "Active" means unconsumed and unexpired. Used by resend to decide
-- whether to reuse the existing token instead of minting a new one.
-- =====================================================


-- name: GetActiveVerificationTokenByUserID :one

SELECT *

FROM email_verification_tokens

WHERE user_id = $1

AND consumed_at IS NULL

AND expires_at > NOW()

ORDER BY created_at DESC

LIMIT 1;



-- =====================================================
-- Consume Token
--
-- Atomic operation. Prevents double verification.
-- =====================================================


-- name: ConsumeVerificationToken :execrows

UPDATE email_verification_tokens

SET consumed_at = NOW()

WHERE id = $1

AND consumed_at IS NULL;
