-- migration-guard: tenant-only
--
-- Milestone 3 part 5.3: a human-proposed deployment mapping for a declared AI-BOM
-- resource, staged separately from the confirmed link so a proposal from one reviewer
-- can be approved (or discarded) by another without ever presenting an unconfirmed
-- guess as a real deployment.
--
-- Deliberately not reusing linked_artifact_id/link_method for the pending stage: those
-- columns' own consistency check (ai_bom_declared_resource_link_consistency_check) requires
-- deployment_state = 'LINKED' whenever they're set, and a proposal is by definition not yet
-- confirmed. Approval moves a proposal into linked_artifact_id/link_method='REVIEWED'/
-- link_reviewed_by, which V7's existing checks already govern -- no change to those needed.

ALTER TABLE ${tenantSchema}.ai_bom_declared_resources
    ADD COLUMN proposed_artifact_id uuid
        REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE SET NULL,
    ADD COLUMN proposed_by varchar(255),
    ADD COLUMN proposed_at timestamptz;

ALTER TABLE ${tenantSchema}.ai_bom_declared_resources
    ADD CONSTRAINT ai_bom_declared_resource_proposal_consistency_check
        CHECK (
            (proposed_artifact_id IS NOT NULL AND proposed_by IS NOT NULL AND proposed_at IS NOT NULL)
            OR (proposed_artifact_id IS NULL AND proposed_by IS NULL AND proposed_at IS NULL)
        );
