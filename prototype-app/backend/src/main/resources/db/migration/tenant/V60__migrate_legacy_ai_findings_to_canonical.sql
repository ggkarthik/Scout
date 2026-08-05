-- Retire the legacy AI findings silo without losing any records created before AI Grid.
-- Canonical findings keep the original UUID so review history can be carried across.

INSERT INTO findings (
    id, tenant_id, finding_kind, fingerprint, workflow_class, status, decision_state,
    creation_source, matched_by, confidence_score, first_observed_at, last_observed_at,
    closed_at, closed_reason, display_id, title, policy_id, policy_version, severity_override,
    risk_score, evidence, reason_code, created_at, updated_at
)
SELECT f.id,
       f.tenant_id,
       'AI_POSTURE',
       md5(f.tenant_id::text || '|AI_POSTURE|' || f.policy_id || '|' || f.artifact_id::text),
       'POSTURE_FINDING',
       CASE WHEN f.status = 'OPEN' THEN 'OPEN' ELSE 'AUTO_CLOSED' END,
       CASE WHEN f.status = 'OPEN' THEN 'AFFECTED' ELSE 'NOT_AFFECTED' END,
       'AI_SECURITY',
       'legacy-ai-migration',
       1.0,
       f.first_observed_at,
       f.last_observed_at,
       CASE WHEN f.status = 'OPEN' THEN NULL ELSE coalesce(f.resolved_at, f.last_observed_at, now()) END,
       CASE WHEN f.status = 'OPEN' THEN NULL ELSE 'AUTO_POLICY_NOT_OWNER_FACING' END,
       'F-' || upper(substr(replace(f.id::text, '-', ''), 1, 12)),
       f.title,
       f.policy_id,
       f.policy_version,
       f.severity,
       CASE f.severity WHEN 'CRITICAL' THEN 9.5 WHEN 'HIGH' THEN 8.0
                       WHEN 'MEDIUM' THEN 5.0 ELSE 2.0 END,
       f.evidence_json,
       'LEGACY_AI_MIGRATION',
       f.first_observed_at,
       f.last_observed_at
  FROM ai_security_findings f
 WHERE NOT EXISTS (select 1 from findings existing where existing.id = f.id)
ON CONFLICT (id) DO NOTHING;

INSERT INTO finding_subjects (id, finding_id, tenant_id, subject_type, subject_id, subject_role)
SELECT gen_random_uuid(), f.id, f.tenant_id, 'ARTIFACT', f.artifact_id, 'PRIMARY'
  FROM ai_security_findings f
 WHERE NOT EXISTS (
           select 1 from finding_subjects subject
            where subject.finding_id = f.id and subject.subject_role = 'PRIMARY'
       )
ON CONFLICT (finding_id, subject_type, subject_id, subject_role) DO NOTHING;

INSERT INTO finding_reviews (id, finding_id, tenant_id, disposition, reason, policy_version, reviewed_by, reviewed_at)
SELECT r.id, r.finding_id, r.tenant_id, r.disposition, r.reason,
       r.policy_version, r.reviewed_by, r.reviewed_at
  FROM ai_security_finding_reviews r
 WHERE EXISTS (select 1 from findings f where f.id = r.finding_id)
ON CONFLICT (id) DO NOTHING;
