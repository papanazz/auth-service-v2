-- =====================================================
-- Add session_id to authentication_events
-- =====================================================
--
-- audit.Event has carried a SessionID field since login/refresh/logout
-- were built, and every one of their event constructors sets it — but
-- with no column to hold it, the mapper silently dropped it on every
-- write. The audit trail has never actually recorded which session a
-- refresh, logout, or login was for.
--
-- Nullable and unconstrained (no FK to sessions), matching user_id in
-- this same table: audit rows must survive independently of the
-- entities they reference, including a session that is later deleted.
-- =====================================================


ALTER TABLE authentication_events

ADD COLUMN session_id UUID;


CREATE INDEX idx_auth_events_session_id

ON authentication_events(session_id);
