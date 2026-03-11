ALTER TABLE IF EXISTS component_vulnerability_states
    ADD COLUMN IF NOT EXISTS applicability_reason_detail text,
    ADD COLUMN IF NOT EXISTS impact_reason_detail text,
    ADD COLUMN IF NOT EXISTS analyst_disposition character varying(40),
    ADD COLUMN IF NOT EXISTS analyst_reason text,
    ADD COLUMN IF NOT EXISTS analyst_updated_by character varying(255),
    ADD COLUMN IF NOT EXISTS analyst_updated_at timestamp(6) with time zone;

ALTER TABLE IF EXISTS component_vulnerability_states
    DROP CONSTRAINT IF EXISTS component_vulnerability_states_impact_state_check;

ALTER TABLE IF EXISTS component_vulnerability_states
    ADD CONSTRAINT component_vulnerability_states_impact_state_check CHECK (
        (impact_state)::text = ANY ((
            ARRAY[
                'IMPACTED'::character varying,
                'NOT_IMPACTED'::character varying,
                'FIXED'::character varying,
                'NO_PATCH'::character varying,
                'UNDER_INVESTIGATION'::character varying,
                'UNKNOWN'::character varying
            ]
        )::text[])
    );

ALTER TABLE IF EXISTS component_vulnerability_states
    DROP CONSTRAINT IF EXISTS component_vulnerability_states_analyst_disposition_check;

ALTER TABLE IF EXISTS component_vulnerability_states
    ADD CONSTRAINT component_vulnerability_states_analyst_disposition_check CHECK (
        analyst_disposition IS NULL
        OR (analyst_disposition)::text = ANY ((
            ARRAY[
                'IMPACTED'::character varying,
                'NOT_IMPACTED'::character varying,
                'UNKNOWN'::character varying
            ]
        )::text[])
    );

ALTER TABLE IF EXISTS org_cve_records
    DROP CONSTRAINT IF EXISTS org_cve_records_impact_state_check;

ALTER TABLE IF EXISTS org_cve_records
    ADD CONSTRAINT org_cve_records_impact_state_check CHECK (
        (impact_state)::text = ANY ((
            ARRAY[
                'IMPACTED'::character varying,
                'NOT_IMPACTED'::character varying,
                'FIXED'::character varying,
                'NO_PATCH'::character varying,
                'UNDER_INVESTIGATION'::character varying,
                'UNKNOWN'::character varying
            ]
        )::text[])
    );
