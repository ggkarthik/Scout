ALTER TABLE org_cve_records
    ADD COLUMN investigation_summary_input_json TEXT,
    ADD COLUMN investigation_summary_output_json TEXT,
    ADD COLUMN investigation_summary_mode VARCHAR(32),
    ADD COLUMN investigation_summary_generated_at TIMESTAMPTZ;
