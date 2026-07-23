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

    public static final String DATASET_VERSION = "customer-demo-v2";
    private static final String ID_NAMESPACE = "customer-demo-v1";

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

    public boolean needsRepair(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> Boolean.TRUE.equals(jdbcTemplate.queryForObject("""
                SELECT EXISTS (
                    SELECT 1
                      FROM bom_ingestion_records
                     WHERE tenant_id = ?
                       AND source_type = 'GITHUB_REPO'
                )
                """, Boolean.class, tenant.getId())));
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
        BomDatasetSummary bomSummary = seedAiAndCryptoBoms(tenantId, assetIds, vulnerabilityIds, now);
        return new DemoDatasetSummary(ASSETS.size(), ASSETS.size(), componentIds.size(), findingIds.size(),
                VULNERABILITIES.size(), 2, bomSummary.aiBoms(), bomSummary.aiComponents(),
                bomSummary.aiFindings(), bomSummary.cboms(), bomSummary.cbomComponents(), bomSummary.cbomFindings());
    }

    private BomDatasetSummary seedAiAndCryptoBoms(
            UUID tenantId,
            List<UUID> assetIds,
            List<UUID> vulnerabilityIds,
            Instant now
    ) {
        List<UUID> aiBomIds = List.of(
                seedBomRecord(tenantId, assetIds.get(0), "ai-bom-checkout", "AI_BOM",
                        "checkout-ai-bom.cdx.json", "Kanra AI Platform", 4, now.minus(2, ChronoUnit.DAYS)),
                seedBomRecord(tenantId, assetIds.get(3), "ai-bom-analytics", "AI_BOM",
                        "analytics-ai-bom.cdx.json", "Kanra Data Science", 4, now.minus(1, ChronoUnit.DAYS))
        );
        List<DemoBomComponent> aiComponents = List.of(
                new DemoBomComponent("kanra-fraud-detector", "2026.07", null, "Proprietary",
                        "Kanra Data Science", "machine-learning-model", "runtime"),
                new DemoBomComponent("pytorch", "2.2.0", "pkg:pypi/torch@2.2.0", "BSD-3-Clause",
                        "PyTorch Foundation", "library", "runtime"),
                new DemoBomComponent("onnxruntime", "1.17.0", "pkg:pypi/onnxruntime@1.17.0", "MIT",
                        "Microsoft", "library", "runtime"),
                new DemoBomComponent("langchain", "0.2.5", "pkg:pypi/langchain@0.2.5", "MIT",
                        "LangChain", "library", "runtime"),
                new DemoBomComponent("kanra-support-rag", "2026.06", null, "Proprietary",
                        "Kanra AI Platform", "machine-learning-model", "runtime"),
                new DemoBomComponent("sentence-transformers", "2.6.1", "pkg:pypi/sentence-transformers@2.6.1",
                        "Apache-2.0", "UKPLab", "library", "runtime"),
                new DemoBomComponent("customer-support-embeddings", "2026-Q2", null, "Internal",
                        "Kanra Data Science", "dataset", "training"),
                new DemoBomComponent("libwebp", "1.3.1", "pkg:generic/libwebp@1.3.1", "BSD-3-Clause",
                        "Google", "library", "runtime")
        );
        List<UUID> aiComponentIds = new ArrayList<>();
        for (int i = 0; i < aiComponents.size(); i++) {
            UUID bomId = aiBomIds.get(i < 4 ? 0 : 1);
            DemoBomComponent component = aiComponents.get(i);
            UUID componentId = stableId(tenantId, "ai-bom-component:" + component.name());
            aiComponentIds.add(componentId);
            jdbcTemplate.update("""
                    INSERT INTO bom_components
                        (id, bom_id, tenant_id, name, version, purl, license, supplier,
                         component_type, category, is_active, properties, bom_ref, scope, workflow_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'AI_MODEL', true, ?::jsonb, ?, ?, 'DISCOVERED')
                    ON CONFLICT (id) DO NOTHING
                    """, componentId, bomId, tenantId, component.name(), component.version(), component.purl(),
                    component.license(), component.supplier(), component.componentType(),
                    "{\"bomType\":\"AI_BOM\",\"purpose\":\"customer-demo\",\"modelRiskTier\":\""
                            + (component.componentType().contains("model") ? "HIGH" : "MEDIUM") + "\"}",
                    "ai:" + component.name(), component.scope());
            jdbcTemplate.update("""
                    INSERT INTO bom_component_evidence
                        (id, tenant_id, bom_component_id, bom_id, evidence_type, evidence_key,
                         evidence_value, source_system, source_reference, created_at)
                    VALUES (?, ?, ?, ?, 'ATTESTATION', 'ai-bom-source', ?,
                            'github', ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """, stableId(tenantId, "ai-evidence:" + component.name()), tenantId, componentId, bomId,
                    component.supplier(), "github.com/kanra/platform/" + (i < 4 ? "checkout" : "analytics"),
                    ts(now.minus(1, ChronoUnit.DAYS)));
        }
        int aiFindingCount = 0;
        int[][] aiLinks = {{1, 5}, {2, 2}, {3, 5}, {5, 3}, {7, 3}};
        for (int[] link : aiLinks) {
            UUID componentId = aiComponentIds.get(link[0]);
            UUID bomId = aiBomIds.get(link[0] < 4 ? 0 : 1);
            DemoVulnerability vulnerability = VULNERABILITIES.get(link[1]);
            UUID vulnerabilityLinkId = stableId(tenantId,
                    "ai-vulnerability-link:" + componentId + ":" + vulnerability.externalId());
            jdbcTemplate.update("""
                    INSERT INTO bom_component_vulnerability_links
                        (id, tenant_id, bom_component_id, bom_id, vulnerability_key,
                         vulnerability_source, relation_type, match_source, match_confidence,
                         direct_match, correlation_evidence_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'NVD', 'CVE', 'AI_BOM_PURL', 96.00, true,
                            ?::jsonb, ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """, vulnerabilityLinkId, tenantId, componentId, bomId, vulnerability.externalId(),
                    "{\"dataset\":\"" + DATASET_VERSION + "\",\"vulnerabilityId\":\""
                            + vulnerabilityIds.get(link[1]) + "\"}", ts(now.minus(1, ChronoUnit.DAYS)), ts(now));
            jdbcTemplate.update("""
                    INSERT INTO bom_component_workflows
                        (id, tenant_id, bom_component_id, vulnerability_link_id, workflow_type,
                         workflow_status, workflow_reason, investigation_key, started_at, updated_at)
                    VALUES (?, ?, ?, ?, 'INVESTIGATION', 'IN_PROGRESS',
                            'AI runtime dependency exposure requires model-serving impact review',
                            ?, ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """, stableId(tenantId, "ai-workflow:" + vulnerabilityLinkId), tenantId, componentId,
                    vulnerabilityLinkId, "AIBOM-" + vulnerability.externalId(),
                    ts(now.minus(1, ChronoUnit.DAYS)), ts(now));
            aiFindingCount++;
        }

        List<UUID> cbomIds = List.of(
                seedBomRecord(tenantId, assetIds.get(0), "cbom-checkout", "CBOM",
                        "checkout-crypto.cbom.json", "Kanra Security Engineering", 4, now.minus(3, ChronoUnit.DAYS)),
                seedBomRecord(tenantId, assetIds.get(4), "cbom-partner", "CBOM",
                        "partner-gateway.cbom.json", "Kanra Platform Security", 4, now.minus(2, ChronoUnit.DAYS))
        );
        List<DemoCbomComponent> cryptoComponents = List.of(
                new DemoCbomComponent("Checkout TLS certificate", "CERTIFICATE", "X.509", 2048,
                        "RSA", null, "TLS termination", 62.0),
                new DemoCbomComponent("Legacy payment signing key", "RELATED_CRYPTO_MATERIAL", "RSA", 1024,
                        "RSA", "vault://payments/legacy-signing", "Payment signature", 88.0),
                new DemoCbomComponent("Legacy receipt digest", "ALGORITHM", "SHA-1", null,
                        null, null, "Receipt integrity", 78.0),
                new DemoCbomComponent("Checkout data encryption", "ALGORITHM", "AES-256-GCM", 256,
                        null, "kms://payments/checkout", "Card-data encryption", 12.0),
                new DemoCbomComponent("Partner gateway TLS", "PROTOCOL", "TLS", null,
                        "TLS 1.0", null, "Partner transport", 82.0),
                new DemoCbomComponent("Partner ECDSA certificate", "CERTIFICATE", "ECDSA", 256,
                        "P-256", null, "Mutual TLS", 48.0),
                new DemoCbomComponent("Partner API signing secret", "RELATED_CRYPTO_MATERIAL", "HMAC-SHA256", 256,
                        null, "env://PARTNER_SIGNING_SECRET", "Webhook signing", 95.0),
                new DemoCbomComponent("Partner RSA encryption key", "RELATED_CRYPTO_MATERIAL", "RSA", 2048,
                        "RSA", "hsm://partner/rsa-primary", "Payload encryption", 45.0)
        );
        List<UUID> cbomComponentIds = new ArrayList<>();
        for (int i = 0; i < cryptoComponents.size(); i++) {
            UUID bomId = cbomIds.get(i < 4 ? 0 : 1);
            UUID assetId = assetIds.get(i < 4 ? 0 : 4);
            DemoCbomComponent component = cryptoComponents.get(i);
            UUID genericId = stableId(tenantId, "cbom-generic-component:" + component.name());
            jdbcTemplate.update("""
                    INSERT INTO bom_components
                        (id, bom_id, tenant_id, name, version, supplier, component_type,
                         category, is_active, properties, bom_ref, scope, workflow_status)
                    VALUES (?, ?, ?, ?, ?, 'Kanra Security Engineering', 'cryptographic-asset',
                            'CRYPTOGRAPHIC', true, ?::jsonb, ?, 'runtime', 'DISCOVERED')
                    ON CONFLICT (id) DO NOTHING
                    """, genericId, bomId, tenantId, component.name(), component.primitive(),
                    "{\"bomType\":\"CBOM\",\"assetType\":\"" + component.assetType() + "\"}",
                    "crypto:" + component.name());
            jdbcTemplate.update("""
                    INSERT INTO bom_component_evidence
                        (id, tenant_id, bom_component_id, bom_id, evidence_type, evidence_key,
                         evidence_value, source_system, source_reference, created_at)
                    VALUES (?, ?, ?, ?, 'CRYPTOGRAPHIC_DECLARATION', 'cbom-asset-type', ?,
                            'github', ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """, stableId(tenantId, "cbom-evidence:" + component.name()), tenantId, genericId, bomId,
                    component.assetType(), "github.com/kanra/platform/"
                            + (i < 4 ? "checkout-crypto.cbom.json" : "partner-gateway.cbom.json"),
                    ts(now.minus(2, ChronoUnit.DAYS)));
            UUID cbomComponentId = stableId(tenantId, "cbom-component:" + component.name());
            cbomComponentIds.add(cbomComponentId);
            jdbcTemplate.update("""
                    INSERT INTO cbom_components
                        (id, tenant_id, asset_id, source_bom_id, bom_ref, component_fingerprint,
                         name, description, asset_type, component_type, primitive, key_size, curve,
                         protocol_version, storage_location, used_in, not_before, not_after,
                         issuer, subject, signature_algorithm, risk_score, active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'cryptographic-asset', ?, ?, ?, ?, ?, ?,
                            current_date - 300, current_date + ?, 'Kanra Internal CA', ?, ?, ?, true, ?, ?)
                    ON CONFLICT (id) DO NOTHING
                    """, cbomComponentId, tenantId, assetId, bomId, "crypto:" + component.name(),
                    stableId(tenantId, "cbom-fingerprint:" + component.name()).toString(),
                    component.name(), "Synthetic CBOM asset for the Kanra customer demonstration",
                    component.assetType(), component.primitive(), component.keySize(),
                    component.curve(), component.curve(), component.storageLocation(), component.usedIn(),
                    i == 0 ? 25 : 365, component.name(), i == 0 ? "sha256WithRSAEncryption" : null,
                    component.riskScore(), ts(now.minus(3, ChronoUnit.DAYS)), ts(now));
        }
        int cbomFindingCount = 0;
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(0), "CBOM-CERT-EXPIRING",
                "CERT_EXPIRY", "MEDIUM", "Checkout certificate expires soon",
                "Renew the public certificate and validate the deployment before expiry.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(1), "CBOM-RSA-SMALL-KEY",
                "KEY_MANAGEMENT", "HIGH", "RSA signing key is below 2048 bits",
                "Rotate the signing key to RSA-3072 or an approved elliptic-curve algorithm.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(1), "CBOM-QUANTUM-VULNERABLE",
                "QUANTUM_VULNERABLE", "MEDIUM", "Signing key is not post-quantum resistant",
                "Track migration to an approved hybrid post-quantum signature scheme.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(2), "CBOM-WEAK-ALGO",
                "WEAK_ALGORITHM", "HIGH", "SHA-1 is used for receipt integrity",
                "Replace SHA-1 with SHA-256 or SHA-384 and reissue stored digests.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(4), "CBOM-DEPRECATED-PROTOCOL",
                "DEPRECATED_PROTOCOL", "HIGH", "Partner endpoint permits TLS 1.0",
                "Require TLS 1.2 or later and remove legacy cipher suites.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(5), "CBOM-QUANTUM-VULNERABLE",
                "QUANTUM_VULNERABLE", "MEDIUM", "ECDSA certificate needs a quantum migration plan",
                "Inventory dependencies and plan hybrid certificate adoption.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(6), "CBOM-MATERIAL-COMPROMISED",
                "CREDENTIAL_EXPOSURE", "CRITICAL", "Partner signing secret is marked compromised",
                "Revoke and rotate the secret immediately, then review webhook access logs.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(6), "CBOM-SECRET-ENV-STORAGE",
                "STORAGE_RISK", "MEDIUM", "Signing secret is stored in an environment variable",
                "Move the secret to the managed vault and use workload identity.", now);
        cbomFindingCount += seedCbomFinding(tenantId, cbomComponentIds.get(7), "CBOM-QUANTUM-VULNERABLE",
                "QUANTUM_VULNERABLE", "MEDIUM", "RSA encryption key is quantum vulnerable",
                "Plan migration to hybrid post-quantum key encapsulation.", now);

        seedCbomPosture(tenantId, assetIds.get(0), cbomIds.get(0), 4, 0, 2, 2, 0, 1, 1, 1, 42.0, now);
        seedCbomPosture(tenantId, assetIds.get(4), cbomIds.get(1), 4, 1, 1, 3, 0, 2, 0, 0, 28.0, now);
        return new BomDatasetSummary(2, aiComponents.size(), aiFindingCount,
                2, cryptoComponents.size(), cbomFindingCount);
    }

    private UUID seedBomRecord(
            UUID tenantId,
            UUID assetId,
            String key,
            String bomType,
            String filename,
            String supplier,
            int componentCount,
            Instant ingestedAt
    ) {
        UUID id = stableId(tenantId, "bom-record:" + key);
        jdbcTemplate.update("""
                INSERT INTO bom_ingestion_records
                    (id, tenant_id, asset_id, bom_type, format, format_version, serial_number,
                     supplier, source_method, source_type, source_system, source_reference,
                     source_label, spec_family, document_format, document_name, content_type,
                     component_count, status, ingested_at, ingested_by)
                VALUES (?, ?, ?, ?, 'CYCLONEDX', '1.6', ?, ?, 'GITHUB_REPO',
                        'GITHUB_REPOSITORY', 'github', ?, ?, 'CYCLONEDX', 'JSON', ?,
                        'application/vnd.cyclonedx+json', ?, 'ACTIVE', ?, 'demo-seeder')
                ON CONFLICT (id) DO UPDATE
                    SET source_type = EXCLUDED.source_type,
                        source_reference = EXCLUDED.source_reference,
                        source_label = EXCLUDED.source_label,
                        document_name = EXCLUDED.document_name
                """, id, tenantId, assetId, bomType, "urn:uuid:" + id, supplier,
                "github.com/kanra/platform/" + filename, filename, filename, componentCount, ts(ingestedAt));
        return id;
    }

    private int seedCbomFinding(
            UUID tenantId,
            UUID componentId,
            String ruleId,
            String riskClass,
            String severity,
            String title,
            String recommendation,
            Instant now
    ) {
        UUID id = stableId(tenantId, "cbom-finding:" + componentId + ":" + ruleId);
        jdbcTemplate.update("""
                INSERT INTO cbom_risk_findings
                    (id, tenant_id, cbom_component_id, rule_id, rule_version, finding_fingerprint,
                     risk_class, severity, title, detail, evidence, recommendation, status,
                     first_seen_at, last_seen_at, created_at)
                VALUES (?, ?, ?, ?, '1', ?, ?, ?, ?,
                        'Detected by the ScoutGrid customer-demo CBOM policy engine.',
                        ?::jsonb, ?, 'OPEN', ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
                """, id, tenantId, componentId, ruleId,
                stableId(tenantId, "cbom-finding-fingerprint:" + componentId + ":" + ruleId).toString(),
                riskClass, severity, title, "{\"dataset\":\"" + DATASET_VERSION + "\"}",
                recommendation, ts(now.minus(2, ChronoUnit.DAYS)), ts(now), ts(now.minus(2, ChronoUnit.DAYS)));
        return 1;
    }

    private void seedCbomPosture(
            UUID tenantId,
            UUID assetId,
            UUID bomId,
            int total,
            int critical,
            int high,
            int medium,
            int low,
            int quantum,
            int weak,
            int expiring,
            double score,
            Instant now
    ) {
        jdbcTemplate.update("""
                INSERT INTO cbom_posture_summary
                    (id, tenant_id, asset_id, last_source_bom_id, total_components,
                     critical_findings, high_findings, medium_findings, low_findings,
                     info_findings, accepted_findings, quantum_vulnerable, weak_algorithms,
                     expiring_certs, posture_score, last_evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, asset_id) DO NOTHING
                """, stableId(tenantId, "cbom-posture:" + assetId), tenantId, assetId, bomId, total,
                critical, high, medium, low, quantum, weak, expiring, score, ts(now));
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
        String namespace = ID_NAMESPACE + ":" + (tenantId == null ? "platform" : tenantId) + ":" + key;
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
            int campaigns,
            int aiBoms,
            int aiComponents,
            int aiFindings,
            int cboms,
            int cbomComponents,
            int cbomFindings
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

    private record DemoBomComponent(
            String name,
            String version,
            String purl,
            String license,
            String supplier,
            String componentType,
            String scope
    ) {
    }

    private record DemoCbomComponent(
            String name,
            String assetType,
            String primitive,
            Integer keySize,
            String curve,
            String storageLocation,
            String usedIn,
            double riskScore
    ) {
    }

    private record BomDatasetSummary(
            int aiBoms,
            int aiComponents,
            int aiFindings,
            int cboms,
            int cbomComponents,
            int cbomFindings
    ) {
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
