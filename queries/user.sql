-- =====================================================
-- Create User
--
-- Creates a new identity account.
--
-- Password is already hashed before reaching repository.
--
-- =====================================================


-- name: CreateUser :one

INSERT INTO users (

    id,

    email,

    password_hash,

    status,

    email_verified_at

)

VALUES (

    $1,

    $2,

    $3,

    $4,

    $5

)

RETURNING *;



-- =====================================================
-- Find User By Email
--
-- Used for:
--
-- - Login
-- - Registration duplicate check
--
-- Email should already be normalized:
--
-- lowercase + trimmed
--
-- =====================================================


-- name: GetUserByEmail :one

SELECT

    *

FROM users

WHERE email = $1

LIMIT 1;



-- =====================================================
-- Find User By ID
--
-- Used for:
--
-- - JWT validation
-- - Profile lookup
-- - Authorization
-- - Refresh token flow
--
-- =====================================================


-- name: GetUserByID :one

SELECT

    *

FROM users

WHERE id = $1

LIMIT 1;



-- =====================================================
-- Update Last Login
--
-- Used after successful authentication.
--
-- This should NOT be in the login transaction that
-- creates session/token because it is not critical.
--
-- Can be async later.
--
-- =====================================================


-- name: UpdateLastLoginAt :exec

UPDATE users

SET

    last_login_at = NOW(),

    updated_at = NOW()

WHERE id = $1;



-- =====================================================
-- Mark Email Verified
--
-- Status is passed in rather than computed here (e.g. PENDING ->
-- ACTIVE): that transition is a domain rule (user.VerifyEmail), and
-- this query just persists whatever the caller decided.
-- =====================================================


-- name: MarkEmailVerified :exec

UPDATE users

SET

    email_verified_at = $2,

    status = $3,

    updated_at = NOW()

WHERE id = $1;