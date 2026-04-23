ALTER TABLE servicenow_cmdb_configs ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ;
