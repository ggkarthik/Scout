-- Purview account name the Azure AI Security connector reads classification results from
-- (read-only Data Map lookups; Scout never creates or runs Purview scans itself).

ALTER TABLE ai_security_connector_configs
    ADD COLUMN IF NOT EXISTS purview_account_name varchar(255);
