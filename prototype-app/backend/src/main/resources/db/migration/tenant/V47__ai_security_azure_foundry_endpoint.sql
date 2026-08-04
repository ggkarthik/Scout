ALTER TABLE ai_security_connector_configs
    ADD COLUMN IF NOT EXISTS foundry_endpoint_url varchar(500);
