-- migration-guard: platform-only
-- Forward-only correction for VALIDATED/PAUSED Phase 1 packages. V76 is intentionally immutable.

UPDATE platform.ai_grid_fact_definitions
   SET value_type = 'STRING'
 WHERE fact_key = 'mcp.target_status'
   AND version = '1.0.0'
   AND value_type = 'BOOLEAN';

UPDATE platform.ai_grid_policy_versions
   SET required_facts_json = '[{"factKey":"mcp.target_status","valueType":"STRING","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]'::jsonb,
       predicate_json = '{"fact":"mcp.target_status","in":["FAILED","UNSYNCHRONIZED"]}'::jsonb,
       package_digest = '4bdf2363a456f890530f521b818c38c702418b1137b20437c1d9efcabef1ea73'
 WHERE policy_id = 'AGCF-AWS-033'
   AND version = '1.0.0'
   AND lifecycle = 'VALIDATED';

UPDATE platform.ai_grid_policy_versions
   SET required_facts_json = '[]'::jsonb,
       predicate_json = '{}'::jsonb,
       package_digest = CASE policy_id
           WHEN 'AGCF-XSP-001' THEN '567ca24019a78b5ed67a3c6c92f03bf88c49cfab67f76a4cdc055c9973c8cdf5'
           WHEN 'AGCF-XSP-002' THEN '323e12ffd312f1c9159941fd8064ccdb0dd14ebe169ba4dad20f7049b4e353a4'
           WHEN 'AGCF-XSP-003' THEN '79ff72666cda3d9e35fe7259bca45aa8998d32e849454f23d4829a80c321686b'
           WHEN 'AGCF-XSP-004' THEN 'a3ced46f504b5e27af0ab59f6ce3767f3fbfd445e2b3845b9ed9b5891e3377fa'
           WHEN 'AGCF-XSP-005' THEN 'eae2d68b420c3704c92c18bd0bd84f46b5d46936b6c4327512d3fc153c98701b'
           WHEN 'AGCF-XSP-006' THEN 'b4b426318f7bbb944e1d2d542aefd780d9552c22fa9eb4ff871d17ef049ce867'
       END
 WHERE policy_id IN ('AGCF-XSP-001','AGCF-XSP-002','AGCF-XSP-003','AGCF-XSP-004','AGCF-XSP-005','AGCF-XSP-006')
   AND version = '1.0.0'
   AND lifecycle = 'VALIDATED';

