-- V1065: cloud_asset_summary — projection view used by CloudAssetQueryService.
-- Returns all assets that originated from cloud discovery (cloud_provider IS NOT NULL),
-- with pre-aggregated open finding count and applicable CVE count per asset.

CREATE OR REPLACE VIEW cloud_asset_summary AS
SELECT
    a.id,
    a.tenant_id,
    a.type,
    a.name,
    a.identifier,
    a.environment,
    a.owner_team,
    a.owner_email,
    a.business_criticality,
    a.state,
    a.cloud_provider,
    a.cloud_region,
    a.cloud_availability_zone,
    a.cloud_account_id,
    a.cloud_resource_type,
    a.cloud_instance_type,
    a.cloud_vpc_id,
    a.cloud_subnet_id,
    a.cloud_arn,
    a.cloud_tags_json,
    a.cloud_launch_time,
    a.last_cmdb_sync_at,
    a.created_at,
    COALESCE((
        SELECT COUNT(*)
        FROM   findings f
        WHERE  f.asset_id = a.id
          AND  f.status NOT IN ('RESOLVED', 'SUPPRESSED')
    ), 0)                               AS open_finding_count,
    COALESCE((
        SELECT COUNT(DISTINCT cvs.vulnerability_id)
        FROM   inventory_components ic
        JOIN   component_vulnerability_states cvs
               ON cvs.component_id = ic.id
        WHERE  ic.asset_id = a.id
          AND  cvs.applicability_state = 'APPLICABLE'
    ), 0)                               AS applicable_cve_count
FROM assets a
WHERE a.cloud_provider IS NOT NULL;
