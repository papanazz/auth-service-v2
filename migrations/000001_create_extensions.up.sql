-- =====================================================
-- Migration: Create PostgreSQL Extensions
--
-- Enables UUID generation support.
--
-- UUID identifiers avoid sequential ID exposure and
-- provide better compatibility for distributed systems.
--
-- =====================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";