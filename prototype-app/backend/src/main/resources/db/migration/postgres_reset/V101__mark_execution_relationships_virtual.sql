-- migration-guard: platform-only
-- Executions remain runtime records. These two relationship definitions describe API projections,
-- not rows accepted by ObservationEnvelopeV1.
UPDATE platform.ai_grid_relationship_definitions
   SET source='VIRTUAL_API',
       description=CASE relationship_type
           WHEN 'EXECUTED_AS' THEN 'Virtual API edge from a runtime execution to its resolved agent or version.'
           ELSE 'Virtual API edge from a participating artifact to a runtime execution.'
       END
 WHERE relationship_type IN ('EXECUTED_AS','PARTICIPATED_IN');
