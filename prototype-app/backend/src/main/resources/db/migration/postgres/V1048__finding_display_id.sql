CREATE SEQUENCE IF NOT EXISTS findings_display_id_seq START WITH 1 INCREMENT BY 1;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS display_id VARCHAR(16);

ALTER TABLE findings
    ALTER COLUMN display_id SET DEFAULT ('Find' || LPAD(nextval('findings_display_id_seq')::text, 5, '0'));

UPDATE findings
SET display_id = 'Find' || LPAD(nextval('findings_display_id_seq')::text, 5, '0')
WHERE display_id IS NULL;

ALTER TABLE findings
    ALTER COLUMN display_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_display_id_unique
    ON findings(display_id);
