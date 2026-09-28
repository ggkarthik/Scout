-- migration-guard: tenant-only
--
-- Bidirectional ticket sync: tracks what Scout has already reflected on each ticket, so
-- finding changes are pushed once and ticket-driven changes are not echoed straight back.

-- The finding status already reflected on the ticket. The push side acts only when the
-- finding's current status differs from this, which is what stops the two directions from
-- ping-ponging: the pull side writes this column in the same transaction as the status change
-- it applied.
ALTER TABLE ${tenantSchema}.findings
    ADD COLUMN incident_pushed_status varchar(32),
    ADD COLUMN incident_pushed_at timestamptz;

-- Existing tickets were created from an open finding and nothing has been pushed since, so
-- their reflected status is the status they were opened with. Leaving this NULL would make the
-- first sync push a redundant "still open" update to every historical ticket.
UPDATE ${tenantSchema}.findings
   SET incident_pushed_status = status
 WHERE incident_id IS NOT NULL
   AND incident_id <> '';

-- Drives the push scan: findings that carry a ticket whose reflected status has drifted.
CREATE INDEX idx_findings_incident_push_pending
    ON ${tenantSchema}.findings(tenant_id, status, incident_pushed_status)
    WHERE incident_id IS NOT NULL;
