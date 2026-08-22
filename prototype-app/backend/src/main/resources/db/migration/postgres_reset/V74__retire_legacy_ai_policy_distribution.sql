-- migration-guard: platform-only
-- V67 only backfilled this table for staged compatibility.  AI Grid has been
-- authoritative for all runtime reads and writes since the consolidation.
DROP TABLE IF EXISTS platform.ai_security_policy_distribution;
