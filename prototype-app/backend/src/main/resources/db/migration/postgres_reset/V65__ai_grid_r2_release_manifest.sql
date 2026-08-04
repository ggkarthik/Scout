-- migration-guard: platform-only
CREATE TABLE platform.ai_grid_release_manifest_items (
    release_id varchar(32) NOT NULL,
    subject_type varchar(32) NOT NULL,
    subject_id varchar(128) NOT NULL,
    subject_version varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, subject_type, subject_id, subject_version),
    CHECK (subject_type IN ('CORRELATION','POLICY'))
);

ALTER TABLE platform.ai_grid_precision_reviews
    ADD COLUMN label_set_version varchar(32) NOT NULL DEFAULT 'R1-LEGACY',
    ADD COLUMN answer_key_run_id uuid REFERENCES platform.ai_grid_answer_key_runs(id);

INSERT INTO platform.ai_grid_release_manifest_items
    (release_id,subject_type,subject_id,subject_version)
VALUES
    ('R2','CORRELATION','R2_EXTERNAL_SENSITIVE_ACCESS','1.0.0'),
    ('R2','CORRELATION','R2_EXCESSIVE_TOOL_PRIVILEGE','1.0.0'),
    ('R2','CORRELATION','R2_UNTRUSTED_AUTONOMOUS_EXECUTION','1.0.0')
ON CONFLICT DO NOTHING;

CREATE FUNCTION platform.reject_ai_grid_release_manifest_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'AI Grid release manifests are immutable';
END $$;

CREATE TRIGGER ai_grid_release_manifest_immutable
BEFORE UPDATE OR DELETE ON platform.ai_grid_release_manifest_items
FOR EACH ROW EXECUTE FUNCTION platform.reject_ai_grid_release_manifest_mutation();

UPDATE platform.tenant_schema_versions
SET target_version=59,status=case when current_version<59 then 'PENDING' else status end,updated_at=now()
WHERE target_version<59;
ALTER TABLE platform.tenant_schema_versions ALTER COLUMN target_version SET DEFAULT 59;
