-- Performance-only indexes for the virtual runtime graph overlay. V7 remains functionally compatible.
CREATE INDEX idx_ai_agent_executions_tenant_agent_evidence
    ON ${tenantSchema}.ai_agent_executions(tenant_id, agent_artifact_id, evidence_time DESC);

CREATE INDEX idx_ai_agent_executions_tenant_version_evidence
    ON ${tenantSchema}.ai_agent_executions(tenant_id, agent_version_artifact_id, evidence_time DESC)
    WHERE agent_version_artifact_id IS NOT NULL;

CREATE INDEX idx_ai_agent_execution_participants_artifact_evidence
    ON ${tenantSchema}.ai_agent_execution_participants(tenant_id, artifact_id, evidence_time DESC, execution_id);
