-- V1087: Change JSONB column in fix_records to TEXT (JSON stored as string)
ALTER TABLE fix_records
    ALTER COLUMN software_entities TYPE TEXT USING software_entities::TEXT;
