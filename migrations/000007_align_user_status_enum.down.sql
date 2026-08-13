-- =====================================================
-- Revert user_status to the pre-alignment labels
-- =====================================================
--
-- This rollback is lossy and cannot be otherwise: the old enum has no label
-- for DELETED, so soft-deleted accounts collapse into DISABLED and the
-- distinction cannot be recovered by re-applying the up migration.
--
-- Reverse mapping:
--
--   PENDING   -> PENDING_VERIFICATION
--   SUSPENDED -> DISABLED
--   DELETED   -> DISABLED   (lossy)
--   ACTIVE, LOCKED -> unchanged
--
-- =====================================================


ALTER TABLE users
    ALTER COLUMN status DROP DEFAULT;


ALTER TYPE user_status
    RENAME TO user_status_new;


CREATE TYPE user_status AS ENUM (

    'ACTIVE',

    'LOCKED',

    'DISABLED',

    'PENDING_VERIFICATION'

);


ALTER TABLE users
    ALTER COLUMN status TYPE user_status
    USING (
        CASE status::text
            WHEN 'PENDING' THEN 'PENDING_VERIFICATION'
            WHEN 'SUSPENDED' THEN 'DISABLED'
            WHEN 'DELETED' THEN 'DISABLED'
            ELSE status::text
        END::user_status
    );


ALTER TABLE users
    ALTER COLUMN status SET DEFAULT 'PENDING_VERIFICATION';


DROP TYPE user_status_new;
