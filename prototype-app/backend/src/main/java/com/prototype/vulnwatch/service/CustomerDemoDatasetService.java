package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Installs the versioned, fictional customer-demo dataset in one tenant schema.
 * Stable identifiers and conflict-safe inserts make the operation restartable.
 */
@Service
public class CustomerDemoDatasetService {

    public static final String DATASET_VERSION = "customer-demo-v1";

    private static final List<DemoVulnerability> VULNERABILITIES = List.of(
            new DemoVulnerability("CVE-2021-44228", "Apache Log4j remote code execution", "CRITICAL", 10.0, 0.975, true),
            new DemoVulnerability("CVE-2022-22965", "Spring Framework remote code execution", "CRITICAL", 9.8, 0.944, true),
            new DemoVulnerability("CVE-2024-3094", "XZ Utils supply-chain backdoor", "CRITICAL", 10.0, 0.876, true),
            new DemoVulnerability("CVE-2023-4863", "libwebp heap buffer overflow", "HIGH", 8.8, 0.812, true),
            new DemoVulnerability("CVE-2024-6387", "OpenSSH signal handler race condition", "HIGH", 8.1, 0.733, true),
            new DemoVulnerability("CVE-2023-44487", "HTTP/2 rapid reset denial of service", "HIGH", 7.5, 0.694, false),
            new DemoVulnerability("CVE-2021-3156", "Sudo Baron Samedit privilege escalation", "HIGH", 7.8, 0.642, true),
            new DemoVulnerability("CVE-2023-34362", "MOVEit Transfer SQL injection", "CRITICAL", 9.8, 0.917, true)
    );

    private static final List<DemoComponent> COMPONENTS = List.of(
            new DemoComponent("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "MAVEN", "log4j-core", "2.14.1"),
            new DemoComponent("pkg:maven/org.springframework/spring-webmvc@5.3.16", "MAVEN", "spring-webmvc", "5.3.16"),
            new DemoComponent("pkg:generic/xz@5.6.0", "GENERIC", "xz", "5.6.0"),
            new DemoComponent("pkg:generic/libwebp@1.3.1", "GENERIC", "libwebp", "1.3.1"),
            new DemoComponent("pkg:deb/debian/openssh-server@9.6p1", "DEBIAN", "openssh-server", "9.6p1"),
            new DemoComponent("pkg:golang/golang.org/x/net@0.12.0", "GO", "golang.org/x/net", "0.12.0"),
            new DemoComponent("pkg:deb/debian/sudo@1.8.31", "DEBIAN", "sudo", "1.8.31"),
            new DemoComponent("pkg:npm/lodash@4.17.20", "NPM", "lodash", "4.17.20")
    );

    private static final List<DemoAsset> ASSETS = List.of(
            new DemoAsset("checkout-api", "Checkout API", "APPLICATION", "CRITICAL", "Production", "Payments", "payments@kanra.example"),
            new DemoAsset("customer-portal", "Customer Portal", "APPLICATION", "HIGH", "Production", "Digital Experience", "web@kanra.example"),
            new DemoAsset("order-worker", "Order Processing Worker", "APPLICATION", "HIGH", "Production", "Fulfilment", "orders@kanra.example"),
            new DemoAsset("analytics-pipeline", "Analytics Pipeline", "APPLICATION", "MEDIUM", "Production", "Data Platform", "data@kanra.example"),
            new DemoAsset("partner-gateway", "Partner API Gateway", "APPLICATION", "HIGH", "Staging", "Platform", "platform@kanra.example"),
            new DemoAsset("admin-console", "Operations Admin Console", "APPLICATION", "MEDIUM", "Development", "Operations", "operations@kanra.example")
    );

    private final JdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public CustomerDemoDatasetService(
            JdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public DemoDatasetSummary seed(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> seedInTenantSchema(tenant));
    }

    private DemoDatasetSummary seedInTenantSchema(Tenant tenant) {
        UUID tenantId = tenant.getId();
        Instant now = Instant.now();
        List<UUID> vulnerabilityIds = seedVulnerabilities(now);
        List<UUID> softwareIds = seedSoftwareIdentities(now);
        List<UUID> assetIds = new ArrayList<>();
        List<UUID> componentIds = new ArrayList<>();
        List<UUID> findingIds = new ArrayList<>();

        for (int assetIndex = 0; assetIndex < ASSETS.size(); assetIndex++) {
            DemoAsset asset = ASSETS.get(assetIndex);
            UUID assetId = stableId(tenantId, "asset:" + asset.identifier());
            UUID uploadId = stableId(tenantId, "sbom:" + asset.identifier());
            assetIds.add(assetId);
            jdbcTemplate.update("""
                    INSERT INTO assets
                        (id, tenant_id, identifier, name, type, state, business_criticality,
                         environment, department, owner_team, owner_email, service_name,
                         created_at, last_inventory_at)
                    VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """, assetId, tenantId, asset.identifier(), asset.name(), asset.type(), asset.criticality(),
                    asset.environment(), asset.department(), asset.department(), asset.ownerEmail(),
                    asset.identifier(), ts(now.minus(70L - assetIndex * 6L, ChronoUnit.DAYS)),
                    ts(now.minus(assetIndex + 1L, ChronoUnit.HOURS)));
            jdbcTemplate.update("""
                    INSERT INTO sbom_uploads
                        (id, tenant_id, asset_id, format, status, original_filename, component_count,
                         findings_generated, content_type, ingestion_source_type, ingestion_source_system,
                         uploaded_at)
                    VALUES (?, ?, ?, 'CYCLONEDX', 'SUCCESS', ?, 4, 3,
                            'application/vnd.cyclonedx+json', 'CI_PIPELINE', 'GitHub Actions', ?)
                    ON CONFLICT (id) DO NOTHING
                    """, uploadId, tenantId, assetId, asset.identifier() + "-cyclonedx.json",
                    ts(now.minus(assetIndex + 1L, ChronoUnit.DAYS)));
            jdbcTemplate.update("""
                    INSERT INTO bom_ingestion_records
                        (id, tenant_id, sbom_upload_id, asset_id, bom_type, format, format_version,
                         serial_number, supplier, source_method, component_count, status, ingested_at, ingested_by)
                    VALUES (?, ?, ?, ?, 'SBOM', 'CYCLONEDX', '1.5', ?, 'Kanra Engineering',
                            'UPLOAD', 4, 'ACTIVE', ?, 'demo-seeder')
                    ON CONFLICT (id) DO NOTHING
                    """, stableId(tenantId, "bom:" + asset.identifier()), tenantId, uploadId, assetId,
                    "urn:uuid:" + uploadId, ts(now.minus(assetIndex + 1L, ChronoUnit.DAYS)));

            for (int slot = 0; slot < 4; slot++) {
                int componentIndex = (assetIndex + slot) % COMPONENTS.size();
                DemoComponent component = COMPONENTS.get(componentIndex);
                UUID componentId = stableId(tenantId, "component:" + asset.identifier() + ":" + component.purl());
                componentIds.add(componentId);
                jdbcTemplate.update("""
                        INSERT INTO inventory_components
                            (id, tenant_id, asset_id, sbom_upload_id, software_identity_id, component_status,
                             ecosystem, package_name, version, purl, normalized_name, normalized_version,
                             normalized_purl, coord_key, ingested_at, last_observed_at)
                        VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, lower(?), ?, ?, ?, ?, ?)
                        ON CONFLICT (id) DO NOTHING
                        """, componentId, tenantId, assetId, uploadId, softwareIds.get(componentIndex),
                        component.ecosystem(), component.name(), component.version(), component.purl(),
                        component.name(), component.version(), component.purl(), component.purl(),
                        ts(now.minus(assetIndex + 1L, ChronoUnit.DAYS)), ts(now.minus(assetIndex + 1L, ChronoUnit.HOURS)));

                if (slot < 3) {
                    UUID vulnerabilityId = vulnerabilityIds.get(componentIndex);
                    DemoVulnerability vulnerability = VULNERABILITIES.get(componentIndex);
                    UUID findingId = stableId(tenantId, "finding:" + asset.identifier() + ":" + vulnerability.externalId());
                    findingIds.add(findingId);
                    String status = findingStatus(assetIndex, slot);
                    String decision = "RESOLVED".equals(status) ? "FIXED"
                            : "SUPPRESSED".equals(status) ? "NOT_AFFECTED" : slot == 2 ? "UNDER_INVESTIGATION" : "AFFECTED";
                    double risk = Math.max(20.0, vulnerability.cvss() * 10.0 - assetIndex * 3.0 - slot);
                    jdbcTemplate.update("""
                            INSERT INTO findings
                                (id, tenant_id, asset_id, component_id, vulnerability_id, display_id,
                                 status, decision_state, creation_source, matched_by, risk_score,
                                 confidence_score, owner_group, assigned_to, first_observed_at,
                                 last_observed_at, created_at, updated_at, due_at, evidence)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'AUTOMATIC', 'PURL', ?, 0.96, ?, ?,
                                    ?, ?, ?, ?, ?, ?::jsonb)
                            ON CONFLICT (id) DO NOTHING
                            """, findingId, tenantId, assetId, componentId, vulnerabilityId,
                            displayId(findingId), status, decision, risk, asset.department(), asset.ownerEmail(),
                            ts(now.minus(45L - assetIndex * 3L, ChronoUnit.DAYS)),
                            ts(now.minus(assetIndex + 1L, ChronoUnit.HOURS)),
                            ts(now.minus(45L - assetIndex * 3L, ChronoUnit.DAYS)),
                            ts(now.minus(slot, ChronoUnit.DAYS)),
                            ts(now.plus(7L + assetIndex * 3L, ChronoUnit.DAYS)),
                            "{\"source\":\"customer-demo\",\"match\":\"" + component.purl() + "\"}");
                    seedFindingHistory(tenantId, findingId, asset, vulnerability, status, now, assetIndex, slot);
                }
            }
        }

        seedOrgCves(tenantId, vulnerabilityIds, now);
        seedOperatingRecords(tenantId, vulnerabilityIds, now);
        return new DemoDatasetSummary(ASSETS.size(), ASSETS.size(), componentIds.size(), findingIds.size(),
                VULNERABILITIES.size(), 2);
    }

    private List<UUID> seedVulnerabilities(Instant now) {
        List<UUID> ids = new ArrayList<>();
        for (int i = 0; i < VULNERABILITIES.size(); i++) {
            DemoVulnerability vulnerability = VULNERABILITIES.get(i);
            UUID proposedId = stableId(null, "vulnerability:" + vulnerability.externalId());
            jdbcTemplate.update("""
                    INSERT INTO platform.vulnerabilities
                        (id, external_id, source, title, description_snippet, cvss_score, severity,
                         epss_score, in_kev, vuln_status, published_at, last_modified_at, created_at, updated_at)
                    VALUES (?, ?, 'NVD', ?, ?, ?, ?, ?, ?, 'Analyzed', ?, ?, ?, ?)
                    ON CONFLICT (external_id) DO NOTHING
                    """, proposedId, vulnerability.externalId(), vulnerability.title(),
                    "Fictionalized customer-demo exposure based on the public " + vulnerability.externalId() + " record.",
                    vulnerability.cvss(), vulnerability.severity(), vulnerability.epss(), vulnerability.inKev(),
                    ts(now.minus(500L + i * 40L, ChronoUnit.DAYS)), ts(now.minus(3L + i, ChronoUnit.DAYS)),
                    ts(now), ts(now));
            UUID actualId = jdbcTemplate.queryForObject(
                    "SELECT id FROM platform.vulnerabilities WHERE external_id = ?",
                    UUID.class, vulnerability.externalId());
            ids.add(actualId);
        }
        return ids;
    }

    private List<UUID> seedSoftwareIdentities(Instant now) {
        List<UUID> ids = new ArrayList<>();
        for (DemoComponent component : COMPONENTS) {
            UUID proposedId = stableId(null, "software:" + component.purl());
            jdbcTemplate.update("""
                    INSERT INTO platform.software_identities
                        (id, canonical_key, display_name, product, purl, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (canonical_key) DO NOTHING
                    """, proposedId, component.purl(), component.name() + " " + component.version(),
                    component.name(), component.purl(), ts(now), ts(now));
            ids.add(jdbcTemplate.queryForObject(
                    "SELECT id FROM platform.software_identities WHERE canonical_key = ?",
                    UUID.class, component.purl()));
        }
        return ids;
    }

    private void seedFindingHistory(
            UUID tenantId,
            UUID findingId,
            DemoAsset asset,
            DemoVulnerability vulnerability,
            String status,
            Instant now,
            int assetIndex,
            int slot
    ) {
        UUID eventId = stableId(tenantId, "finding-event:" + findingId);
        jdbcTemplate.update("""
                INSERT INTO finding_events
                    (id, finding_id, actor, event_type, summary, details_json, created_at)
                VALUES (?, ?, 'correlation-engine', 'DETECTED', ?, ?::jsonb, ?)
                ON CONFLICT (id) DO NOTHING
                """, eventId, findingId, vulnerability.externalId() + " detected in " + asset.name(),
                "{\"dataset\":\"" + DATASET_VERSION + "\"}",
                ts(now.minus(40L - assetIndex * 3L, ChronoUnit.DAYS)));
        UUID commentId = stableId(tenantId, "finding-comment:" + findingId);
        String body = switch (status) {
            case "RESOLVED" -> "Upgrade verified in the latest build; awaiting normal release evidence retention.";
            case "SUPPRESSED" -> "Compensating control reviewed and approved for this non-production workload.";
            default -> slot == 2
                    ? "Security engineering is validating exploitability and reachable code paths."
                    : "Owner notified; remediation is planned for the current sprint.";
        };
        jdbcTemplate.update("""
                INSERT INTO finding_comments (id, finding_id, author, body, created_at)
                VALUES (?, ?, 'security@kanra.example', ?, ?)
                ON CONFLICT (id) DO NOTHING
                """, commentId, findingId, body, ts(now.minus(2L + assetIndex, ChronoUnit.DAYS)));
    }

    private void seedOrgCves(UUID tenantId, List<UUID> vulnerabilityIds, Instant now) {
        for (int i = 0; i < VULNERABILITIES.size(); i++) {
            DemoVulnerability vulnerability = VULNERABILITIES.get(i);
            String impactState = i == 6 ? "FIXED" : i == 7 ? "UNDER_INVESTIGATION" : "IMPACTED";
            boolean impacted = !"FIXED".equals(impactState);
            jdbcTemplate.update("""
                    INSERT INTO org_cve_records
                        (id, tenant_id, vulnerability_id, external_id, severity, cvss_score, epss_score,
                         in_kev, applicability_state, impact_state, impacted, impact_reason, org_impact,
                         matched_asset_count, matched_component_count, matched_software_count,
                         applicable_component_count, impacted_component_count, fixed_component_count,
                         no_patch_component_count, not_affected_component_count,
                         under_investigation_component_count, unknown_component_count,
                         eol_component_count, eos_component_count, created_at, updated_at, last_evaluated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APPLICABLE', ?, ?, ?,
                            ?, 3, 3, 1, 3, ?, ?, 0, 0, ?, 0, 0, 0, ?, ?, ?)
                    ON CONFLICT (tenant_id, vulnerability_id) DO NOTHING
                    """, stableId(tenantId, "org-cve:" + vulnerability.externalId()), tenantId,
                    vulnerabilityIds.get(i), vulnerability.externalId(), vulnerability.severity(),
                    vulnerability.cvss(), vulnerability.epss(), vulnerability.inKev(), impactState, impacted,
                    "Vulnerable component observed in active application inventory",
                    vulnerability.severity().equals("CRITICAL") ? "HIGH" : "MEDIUM",
                    impacted ? 3L : 0L, "FIXED".equals(impactState) ? 3L : 0L,
                    "UNDER_INVESTIGATION".equals(impactState) ? 3L : 0L,
                    ts(now.minus(30, ChronoUnit.DAYS)), ts(now), ts(now.minus(2, ChronoUnit.HOURS)));
        }
    }

    private void seedOperatingRecords(UUID tenantId, List<UUID> vulnerabilityIds, Instant now) {
        jdbcTemplate.update("""
                INSERT INTO risk_policies
                    (id, tenant_id, asset_critical_sla_multiplier, asset_high_sla_multiplier,
                     asset_medium_sla_multiplier, asset_low_sla_multiplier, auto_close_after_days,
                     auto_close_enabled, critical_sla_days, critical_threshold, high_sla_days,
                     high_threshold, medium_sla_days, low_sla_days, finding_generation_mode, updated_at)
                VALUES (?, ?, 0.5, 0.75, 1.0, 1.5, 14, true, 3, 90, 14, 70, 30, 90, 'AUTO', ?)
                ON CONFLICT (tenant_id) DO NOTHING
                """, stableId(tenantId, "risk-policy"), tenantId, ts(now));
        jdbcTemplate.update("""
                INSERT INTO ownership_rules
                    (id, tenant_id, name, execution_order, user_group, condition_json, created_at, updated_at)
                VALUES (?, ?, 'Critical production services', 10, 'Application Security',
                        '{"environment":"Production","criticality":["CRITICAL","HIGH"]}', ?, ?)
                ON CONFLICT (id) DO NOTHING
                """, stableId(tenantId, "ownership-rule"), tenantId, ts(now.minus(60, ChronoUnit.DAYS)), ts(now));
        jdbcTemplate.update("""
                INSERT INTO suppression_rules
                    (id, tenant_id, name, condition_logic, conditions_json, reason, record_type,
                     state, valid_from, valid_to, created_at, updated_at)
                VALUES (?, ?, 'Development-only compensating control', 'ALL',
                        '{"environment":"Development","severity":["LOW","MEDIUM"]}'::jsonb,
                        'Non-production workload with network isolation', 'FINDING', 'APPROVED',
                        ?, ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
                """, stableId(tenantId, "suppression-rule"), tenantId,
                ts(now.minus(20, ChronoUnit.DAYS)), ts(now.plus(70, ChronoUnit.DAYS)),
                ts(now.minus(20, ChronoUnit.DAYS)), ts(now));

        for (int i = 0; i < 4; i++) {
            DemoVulnerability vulnerability = VULNERABILITIES.get(i);
            jdbcTemplate.update("""
                    INSERT INTO fix_records
                        (id, tenant_id, cve_id, fix_type, recommendation_source, summary, description,
                         software_entities, source_urls, related_cve_ids, generated_at, created_at, updated_at)
                    VALUES (?, ?, ?, 'UPGRADE', 'ScoutGrid demo intelligence', ?, ?,
                            '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, ?, ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """, stableId(tenantId, "fix:" + vulnerability.externalId()), tenantId,
                    vulnerability.externalId(), "Upgrade affected package for " + vulnerability.externalId(),
                    "Upgrade to the vendor-fixed release, rebuild the artifact, and verify with a fresh SBOM.",
                    ts(now.minus(i + 1L, ChronoUnit.DAYS)), ts(now.minus(i + 1L, ChronoUnit.DAYS)), ts(now));
        }

        UUID campaignOne = seedCampaign(tenantId, "Critical internet-facing remediation",
                "Remediate actively exploited issues in production applications", "ACTIVE", now.plus(14, ChronoUnit.DAYS), now);
        UUID campaignTwo = seedCampaign(tenantId, "Q3 open-source hygiene",
                "Reduce high-risk dependency backlog before the quarterly release", "DRAFT", now.plus(40, ChronoUnit.DAYS), now);
        for (int i = 0; i < 4; i++) {
            UUID campaignId = i < 2 ? campaignOne : campaignTwo;
            DemoVulnerability vulnerability = VULNERABILITIES.get(i);
            jdbcTemplate.update("""
                    INSERT INTO campaign_vulnerabilities
                        (id, campaign_id, vulnerability_id, external_id, title, severity, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (campaign_id, external_id) DO NOTHING
                    """, stableId(tenantId, "campaign-vulnerability:" + campaignId + ":" + vulnerability.externalId()),
                    campaignId, vulnerabilityIds.get(i), vulnerability.externalId(), vulnerability.title(),
                    vulnerability.severity(), ts(now.minus(5, ChronoUnit.DAYS)));
        }
        jdbcTemplate.update("""
                INSERT INTO campaign_notes (id, campaign_id, author, body, created_at)
                VALUES (?, ?, 'security@kanra.example',
                        'Payment and customer-facing services are prioritized for the first release train.', ?)
                ON CONFLICT (id) DO NOTHING
                """, stableId(tenantId, "campaign-note:" + campaignOne), campaignOne, ts(now.minus(2, ChronoUnit.DAYS)));
        jdbcTemplate.update("""
                INSERT INTO campaign_activities
                    (id, campaign_id, activity_type, actor, body, metadata_json, created_at)
                VALUES (?, ?, 'OWNER_NOTIFIED', 'demo-seeder',
                        'Application owners received the remediation brief.', '{"channel":"email"}'::jsonb, ?)
                ON CONFLICT (id) DO NOTHING
                """, stableId(tenantId, "campaign-activity:" + campaignOne), campaignOne, ts(now.minus(1, ChronoUnit.DAYS)));

        for (int i = 0; i < 5; i++) {
            jdbcTemplate.update("""
                    INSERT INTO audit_events
                        (id, tenant_id, occurred_at, actor_subject, actor_role, action,
                         target_type, target_id, outcome, details_json)
                    VALUES (?, ?, ?, 'demo-operator@kanra.example', 'TENANT_ADMIN', ?,
                            'demo-dataset', ?, 'SUCCESS', ?::jsonb)
                    ON CONFLICT (id) DO NOTHING
                    """, stableId(tenantId, "audit:" + i), tenantId, ts(now.minus(i + 1L, ChronoUnit.DAYS)),
                    i == 0 ? "campaign.created" : i == 1 ? "finding.assigned" : "sbom.ingested",
                    DATASET_VERSION + "-" + i, "{\"synthetic\":true}");
        }
        jdbcTemplate.update("""
                INSERT INTO platform.sync_runs
                    (id, tenant_id, sync_type, run_scope, status, started_at, completed_at,
                     records_fetched, records_inserted, records_updated, records_failed, metadata_json)
                VALUES (?, ?, 'SBOM_INGESTION', 'TENANT', 'SUCCESS', ?, ?, 24, 24, 0, 0,
                        '{"source":"customer-demo"}')
                ON CONFLICT (id) DO NOTHING
                """, stableId(tenantId, "sync-run"), tenantId, ts(now.minus(1, ChronoUnit.DAYS)),
                ts(now.minus(1, ChronoUnit.DAYS).plus(2, ChronoUnit.MINUTES)));
    }

    private UUID seedCampaign(
            UUID tenantId,
            String name,
            String summary,
            String status,
            Instant dueAt,
            Instant now
    ) {
        UUID id = stableId(tenantId, "campaign:" + name);
        jdbcTemplate.update("""
                INSERT INTO campaigns
                    (id, tenant_id, name, summary, status, created_by, due_at, started_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'security@kanra.example', ?, ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
                """, id, tenantId, name, summary, status, ts(dueAt),
                "ACTIVE".equals(status) ? ts(now.minus(5, ChronoUnit.DAYS)) : null,
                ts(now.minus(7, ChronoUnit.DAYS)), ts(now));
        return id;
    }

    private String findingStatus(int assetIndex, int slot) {
        if (assetIndex == 5 && slot == 2) {
            return "SUPPRESSED";
        }
        if ((assetIndex + slot) % 7 == 0 && assetIndex > 0) {
            return "RESOLVED";
        }
        return "OPEN";
    }

    private String displayId(UUID id) {
        return "DEM-" + id.toString().substring(0, 8).toUpperCase();
    }

    private UUID stableId(UUID tenantId, String key) {
        String namespace = DATASET_VERSION + ":" + (tenantId == null ? "platform" : tenantId) + ":" + key;
        return UUID.nameUUIDFromBytes(namespace.getBytes(StandardCharsets.UTF_8));
    }

    private Timestamp ts(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    public record DemoDatasetSummary(
            int assets,
            int sboms,
            int components,
            int findings,
            int cves,
            int campaigns
    ) {
    }

    private record DemoVulnerability(
            String externalId,
            String title,
            String severity,
            double cvss,
            double epss,
            boolean inKev
    ) {
    }

    private record DemoComponent(String purl, String ecosystem, String name, String version) {
    }

    private record DemoAsset(
            String identifier,
            String name,
            String type,
            String criticality,
            String environment,
            String department,
            String ownerEmail
    ) {
    }
}
