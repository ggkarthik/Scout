-- V1086: Change TEXT[] columns in fix_records to TEXT (JSON stored as string)
ALTER TABLE fix_records
    ALTER COLUMN related_cve_ids TYPE TEXT USING array_to_json(related_cve_ids)::TEXT,
    ALTER COLUMN source_urls     TYPE TEXT USING array_to_json(source_urls)::TEXT;
