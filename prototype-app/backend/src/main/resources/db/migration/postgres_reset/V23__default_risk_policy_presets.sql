-- Backfill tenant risk policies with the product default findings-score preset.
-- Fresh tenants already get the preset from the entity/service defaults; this
-- migration updates existing rows that were still using an empty config.

UPDATE risk_policies
SET findings_score_config = $$[
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
]$$::jsonb
WHERE findings_score_config IS NULL OR findings_score_config = '[]'::jsonb;
