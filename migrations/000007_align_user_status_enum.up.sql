-- =====================================================
-- Align user_status with the domain model
-- =====================================================
--
-- The enum and internal/domain/user.Status had drifted apart:
--
--   database              domain
--   --------              ------
--   ACTIVE                ACTIVE
--   LOCKED                LOCKED
--   DISABLED              (none)
--   PENDING_VERIFICATION  (none)
--   (none)                PENDING
--   (none)                SUSPENDED
--   (none)                DELETED
--
-- The repository casts the domain value straight into the enum, so any write
-- of PENDING, SUSPENDED, or DELETED fails at runtime with an invalid input
-- value. user.New() and user.Suspend() both produce such values, which makes
-- the mismatch a latent outage rather than a cosmetic difference.
--
-- The domain is the source of truth, so the enum moves.
--
-- Mapping applied to existing rows:
--
--   PENDING_VERIFICATION -> PENDING
--   DISABLED             -> SUSPENDED
--   ACTIVE, LOCKED       -> unchanged
--
-- The type is recreated rather than patched with ALTER TYPE ... ADD VALUE:
-- recreation runs safely inside migrate's transaction and makes the data
-- mapping explicit, whereas ADD VALUE cannot drop the two obsolete labels.
--
-- =====================================================


-- The default references the old type and must be detached before the swap.
ALTER TABLE users
    ALTER COLUMN status DROP DEFAULT;


ALTER TYPE user_status
    RENAME TO user_status_old;


CREATE TYPE user_status AS ENUM (

    'PENDING',

    'ACTIVE',

    'SUSPENDED',

    'LOCKED',

    'DELETED'

);


ALTER TABLE users
    ALTER COLUMN status TYPE user_status
    USING (
        CASE status::text
            WHEN 'PENDING_VERIFICATION' THEN 'PENDING'
            WHEN 'DISABLED' THEN 'SUSPENDED'
            ELSE status::text
        END::user_status
    );


ALTER TABLE users
    ALTER COLUMN status SET DEFAULT 'PENDING';


DROP TYPE user_status_old;
