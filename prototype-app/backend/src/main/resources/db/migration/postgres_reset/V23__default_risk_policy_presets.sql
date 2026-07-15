-- Backfill tenant risk policies with the product default findings-score preset.
-- Fresh tenants already get the preset from the entity/service defaults; this
-- migration updates existing rows that were still using an empty config.

DO $$
DECLARE
    schema_record record;
    preset jsonb := $json$[
      {
        "table": "VULNERABILITY",
        "column": "cvssScore",
        "values": [
          { "operator": ">=", "value": "9", "weight": 0.2 },
          { "operator": "<=", "value": "8", "weight": 0.1 }
        ]
      },
      {
        "table": "VULNERABILITY",
        "column": "exploitExists",
        "values": [
          { "operator": "=", "value": "true", "weight": 0.2 }
        ]
      },
      {
        "table": "ASSET",
        "column": "businessCriticality",
        "values": [
          { "operator": "=", "value": "high", "weight": 0.2 }
        ]
      },
      {
        "table": "ASSET",
        "column": "internetFacing",
        "values": [
          { "operator": "=", "value": "true", "weight": 0.2 }
        ]
      },
      {
        "table": "VULNERABILITY",
        "column": "isInKev",
        "values": [
          { "operator": "=", "value": "true", "weight": 0.2 }
        ]
      }
    ]$json$::jsonb;
BEGIN
    FOR schema_record IN
        SELECT table_schema
        FROM information_schema.tables
        WHERE table_name = 'risk_policies'
          AND table_schema NOT IN ('information_schema', 'pg_catalog')
    LOOP
        EXECUTE format(
                'UPDATE %I.risk_policies
                 SET findings_score_config = $1
                 WHERE findings_score_config IS NULL OR findings_score_config = ''[]''::jsonb',
                schema_record.table_schema
        )
        USING preset;
    END LOOP;
END
$$;
