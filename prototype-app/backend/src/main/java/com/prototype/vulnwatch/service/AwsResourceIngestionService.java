package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsResourceRecord;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationRequest;
import software.amazon.awssdk.services.ssm.model.InstanceInformation;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesRequest;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesResponse;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Core ingestion service for AWS cloud resources. Upserts {@link Asset} records
 * with cloud metadata for EC2 compute instances.
 * <p>
 * EC2 instances with SSM-sourced package data are delegated to
 * {@link CmdbIngestionService} so they follow the same path as SCCM.
 */
@Service
public class AwsResourceIngestionService {

    private static final Logger LOG = LoggerFactory.getLogger(AwsResourceIngestionService.class);
    private static final int FLUSH_INTERVAL = 100;

    private final AssetRepository assetRepository;
    private final CiRepository ciRepository;
    private final CmdbIngestionService cmdbIngestionService;
    private final ObjectMapper objectMapper;
    private final EntityManager entityManager;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public AwsResourceIngestionService(
            AssetRepository assetRepository,
            CiRepository ciRepository,
            CmdbIngestionService cmdbIngestionService,
            ObjectMapper objectMapper,
            EntityManager entityManager,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.assetRepository = assetRepository;
        this.ciRepository = ciRepository;
        this.cmdbIngestionService = cmdbIngestionService;
        this.objectMapper = objectMapper;
        this.entityManager = entityManager;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public record IngestionResult(
            int assetsUpserted,
            int inventoryComponentsCreated,
            int inventoryComponentsUpdated,
            int assetsMarkedInactive
    ) {}

    public record SsmInventoryIngestionSummary(
            int assetsIngested,
            int softwareInstancesCreated,
            int softwareInstancesUpdated,
            int inventoryComponentsCreated,
            int inventoryComponentsUpdated,
            int findingsGenerated
    ) {}

    // ── Main entry point ────────────────────────────────────────────────────────────────────────

    @Transactional
    public IngestionResult ingestAll(
            List<AwsResourceRecord> records,
            AwsDiscoveryConfig config,
            Tenant tenant,
            Instant runStartTime
    ) {
        return ingestAll(records, config, tenant, runStartTime, config == null ? null : config.getAwsAccountId());
    }

    @Transactional
    public IngestionResult ingestAll(
            List<AwsResourceRecord> records,
            AwsDiscoveryConfig config,
            Tenant tenant,
            Instant runStartTime,
            String awsAccountId
    ) {
        if (records == null || records.isEmpty()) {
            return new IngestionResult(0, 0, 0, 0);
        }

        Set<String> seenResourceIdentifiers = new LinkedHashSet<>();
        Set<CloudScope> observedScopes = new HashSet<>();

        int assetsUpserted = 0;
        int componentsCreated = 0;
        int componentsUpdated = 0;
        int index = 0;

        for (AwsResourceRecord record : records) {
            if (!hasText(record.arn()) || !"EC2".equalsIgnoreCase(record.resourceType())) {
                continue;
            }
            String resourceIdentifier = canonicalResourceIdentifier(record, awsAccountId);
            seenResourceIdentifiers.add(resourceIdentifier);
            observedScopes.add(scopeFor(record.resourceType(), record.region()));

            Asset asset = upsertAsset(record, config, tenant, resourceIdentifier);
            assetsUpserted++;

            index++;
            if (index % FLUSH_INTERVAL == 0) {
                entityManager.flush();
                entityManager.clear();
            }
        }

        entityManager.flush();

        // Mark stale assets INACTIVE only inside scopes this run actually observed.
        int markedInactive = markStaleAssetsInactive(
                tenant,
                config,
                seenResourceIdentifiers,
                observedScopes,
                runStartTime,
                awsAccountId
        );

        return new IngestionResult(assetsUpserted, componentsCreated, componentsUpdated, markedInactive);
    }

    // ── Asset upsert ─────────────────────────────────────────────────────────────────────────────

    private Asset upsertAsset(
            AwsResourceRecord record,
            AwsDiscoveryConfig config,
            Tenant tenant,
            String resourceIdentifier
    ) {
        Asset asset = findExistingCloudAsset(tenant, record, resourceIdentifier)
                .orElseGet(() -> {
                    Asset a = new Asset();
                    a.setTenant(tenant);
                    a.setCloudProvider("aws");
                    return a;
                });
        asset.setIdentifier(resourceIdentifier);

        asset.setType(AssetType.HOST);
        asset.setName(hasText(record.name()) ? record.name() : record.arn());

        // Cloud metadata
        asset.setCloudProvider("aws");
        asset.setCloudRegion(record.region());
        asset.setCloudAvailabilityZone(record.availabilityZone());
        asset.setCloudAccountId(hasText(record.accountId()) ? record.accountId()
                : config.getAwsAccountId());
        asset.setCloudResourceType(record.resourceType());
        asset.setCloudInstanceType(record.instanceType());
        asset.setCloudVpcId(record.vpcId());
        asset.setCloudSubnetId(record.subnetId());
        asset.setCloudArn(resourceIdentifier);
        asset.setCloudLaunchTime(record.launchTime());
        asset.setMissingIamInstanceProfile(!hasText(record.iamInstanceProfileArn()));
        asset.setSsmManaged(false);
        asset.setSsmInventoryAvailable(false);

        // Serialize all tags to JSON
        if (record.tags() != null && !record.tags().isEmpty()) {
            asset.setCloudTagsJson(toJson(record.tags()));
        }

        // Map state
        asset.setState(mapState(record.state()));
        asset.setLastCmdbSyncAt(Instant.now());

        asset = assetRepository.save(asset);

        // EC2 instances are typed HOST and must have a Ci record so the
        // Host Inventory view can load their detail page.
        if (AssetType.HOST.equals(asset.getType())) {
            upsertCi(record, asset, tenant);
        }

        return asset;
    }

    private void upsertCi(AwsResourceRecord record, Asset asset, Tenant tenant) {
        String sysId = asset.getIdentifier();
        Ci ci = tenantSchemaExecutionService.run(tenant, () -> ciRepository.findBySysId(sysId)
                .or(() -> asset.getId() == null
                        ? Optional.empty()
                        : ciRepository.findByAsset_Id(asset.getId()))
                .orElseGet(() -> {
                    Ci c = new Ci();
                    c.setTenant(tenant);
                    c.setAsset(asset);
                    return c;
                }));
        ci.setSysId(sysId);
        ci.setAsset(asset);
        ci.setDisplayName(hasText(record.name()) ? record.name() : sysId);
        if (hasText(asset.getEnvironment())) ci.setEnvironment(asset.getEnvironment());
        if (asset.getBusinessCriticality() != null) ci.setBusinessCriticality(asset.getBusinessCriticality());
        if (hasText(asset.getOwnerTeam())) ci.setManagedBy(asset.getOwnerTeam());
        ci.setLastCmdbSyncAt(Instant.now());
        ci.touch();
        ciRepository.save(ci);
    }

    // ── EC2 + SSM package ingestion ───────────────────────────────────────────────────────────────

    /**
     * For EC2 instances that are SSM-managed, fetch the installed package inventory via
     * AWS SSM and feed it into {@link CmdbIngestionService} exactly as SCCM does —
     * enabling full CPE-based vulnerability correlation for those instances.
     */
    @Transactional
    public SsmInventoryIngestionSummary ingestEc2SsmPackages(
            List<AwsResourceRecord> ec2Records,
            AwsCredentialsProvider creds,
            List<String> regions,
            Tenant tenant,
            String awsAccountId
    ) {
        int assetsIngested = 0;
        int softwareInstancesCreated = 0;
        int softwareInstancesUpdated = 0;
        int inventoryComponentsCreated = 0;
        int inventoryComponentsUpdated = 0;
        int findingsGenerated = 0;

        for (String region : regions) {
            try (SsmClient ssm = SsmClient.builder()
                    .region(Region.of(region))
                    .credentialsProvider(creds)
                    .build()) {

                for (AwsResourceRecord ec2 : ec2Records) {
                    if (!"EC2".equals(ec2.resourceType()) || !region.equals(ec2.region())) continue;
                    String instanceId = extractInstanceId(ec2.arn());
                    if (!hasText(instanceId)) continue;

                    try {
                        InstanceInformation ssmInfo = describeSsmInstance(ssm, instanceId);
                        updateSsmRegistrationState(ec2, awsAccountId, ssmInfo);
                        if (ssmInfo == null) continue;

                        SsmPackageFetch packageFetch = fetchSsmPackageRows(ssm, instanceId, ec2, awsAccountId);
                        updateSsmInventoryState(ec2, awsAccountId, !packageFetch.rows().isEmpty(), packageFetch.captureTime());
                        if (packageFetch.rows().isEmpty()) continue;

                        List<Map<String, String>> discoveryRows = List.of(); // SSM has no separate discovery model
                        CmdbInventorySyncResponse response = cmdbIngestionService.ingestRows(
                                tenant,
                                "aws",
                                packageFetch.rows(),
                                discoveryRows,
                                new CmdbIngestionService.HostInventorySourceDescriptor(
                                        "aws-ssm-inventory",
                                        "aws-ssm",
                                        "aws",
                                        "AWS:Application",
                                        "https://ssm." + region + ".amazonaws.com",
                                        "application/json",
                                        null
                                )
                        );
                        assetsIngested += response.assetsIngested();
                        softwareInstancesCreated += response.softwareInstancesCreated();
                        softwareInstancesUpdated += response.softwareInstancesUpdated();
                        inventoryComponentsCreated += response.inventoryComponentsCreated();
                        inventoryComponentsUpdated += response.inventoryComponentsUpdated();
                        findingsGenerated += response.findingsRecomputed();
                        LOG.debug("SSM package ingestion complete for EC2 instance {}", instanceId);
                    } catch (Exception e) {
                        LOG.warn("SSM package ingestion failed for EC2 {}: {}", instanceId, e.getMessage());
                    }
                }
            } catch (Exception e) {
                LOG.warn("SSM client setup failed for region {}: {}", region, e.getMessage());
            }
        }
        return new SsmInventoryIngestionSummary(
                assetsIngested,
                softwareInstancesCreated,
                softwareInstancesUpdated,
                inventoryComponentsCreated,
                inventoryComponentsUpdated,
                findingsGenerated
        );
    }

    private InstanceInformation describeSsmInstance(SsmClient ssm, String instanceId) {
        try {
            return ssm.describeInstanceInformationPaginator(DescribeInstanceInformationRequest.builder()
                    .filters(software.amazon.awssdk.services.ssm.model.InstanceInformationStringFilter.builder()
                            .key("InstanceIds")
                            .values(instanceId)
                            .build())
                    .build()
            ).instanceInformationList().stream().findFirst().orElse(null);
        } catch (Exception e) {
            LOG.debug("SSM DescribeInstanceInformation failed for {}: {}", instanceId, e.getMessage());
            return null;
        }
    }

    private SsmPackageFetch fetchSsmPackageRows(
            SsmClient ssm,
            String instanceId,
            AwsResourceRecord ec2,
            String awsAccountId
    ) {
        List<Map<String, String>> rows = new ArrayList<>();
        Instant[] captureTimeHolder = new Instant[1];
        String ciSysId = canonicalResourceIdentifier(ec2, awsAccountId);
        try {
            String nextToken = null;
            do {
                ListInventoryEntriesResponse page = ssm.listInventoryEntries(ListInventoryEntriesRequest.builder()
                        .instanceId(instanceId)
                        .typeName("AWS:Application")
                        .nextToken(nextToken)
                        .build());
                if (captureTimeHolder[0] == null) {
                    captureTimeHolder[0] = parseInstant(page.captureTime());
                }
                if (page.entries() != null) {
                    page.entries().forEach(item -> {
                        Map<String, String> row = new HashMap<>();
                        row.put("hostname", ec2.name());
                        row.put("ci_sys_id", ciSysId);
                        row.put("display_name", item.getOrDefault("Name", ""));
                        row.put("publisher", item.getOrDefault("Publisher", ""));
                        row.put("version", item.getOrDefault("Version", ""));
                        row.put("environment", ec2.tags() != null ? ec2.tags().getOrDefault("Environment", "") : "");
                        rows.add(row);
                    });
                }
                nextToken = page.nextToken();
            } while (hasText(nextToken));
        } catch (Exception e) {
            LOG.warn("SSM ListInventoryEntries failed for {}: {}", instanceId, e.getMessage(), e);
        }
        return new SsmPackageFetch(rows, captureTimeHolder[0]);
    }

    private void updateSsmRegistrationState(AwsResourceRecord ec2, String awsAccountId, InstanceInformation info) {
        updateSsmAsset(ec2, awsAccountId, asset -> {
            asset.setSsmManaged(info != null);
            asset.setSsmPingStatus(info == null ? null : info.pingStatusAsString());
            asset.setSsmLastPingAt(info == null ? null : info.lastPingDateTime());
            if (info == null) {
                asset.setSsmInventoryAvailable(false);
                asset.setSsmInventoryLastCapturedAt(null);
            }
        });
    }

    private void updateSsmInventoryState(AwsResourceRecord ec2, String awsAccountId, boolean available, Instant capturedAt) {
        updateSsmAsset(ec2, awsAccountId, asset -> {
            asset.setSsmInventoryAvailable(available);
            asset.setSsmInventoryLastCapturedAt(available ? capturedAt : null);
        });
    }

    private void updateSsmAsset(AwsResourceRecord ec2, String awsAccountId, java.util.function.Consumer<Asset> updater) {
        String identifier = canonicalResourceIdentifier(ec2, awsAccountId);
        assetRepository.findByIdentifier(identifier).ifPresent(asset -> {
            updater.accept(asset);
            assetRepository.save(asset);
        });
    }

    private String extractInstanceId(String arn) {
        if (!hasText(arn)) return null;
        int slash = arn.lastIndexOf('/');
        return slash >= 0 ? arn.substring(slash + 1) : null;
    }

    // ── Stale asset handling ──────────────────────────────────────────────────────────────────────

    private int markStaleAssetsInactive(
            Tenant tenant,
            AwsDiscoveryConfig config,
            Set<String> seenResourceIdentifiers,
            Set<CloudScope> observedScopes,
            Instant runStartTime,
            String targetAccountId
    ) {
        String awsAccountId = hasText(targetAccountId) ? targetAccountId : config.getAwsAccountId();
        if (!hasText(awsAccountId)) return 0;
        if (seenResourceIdentifiers == null || seenResourceIdentifiers.isEmpty()
                || observedScopes == null || observedScopes.isEmpty()) {
            return 0;
        }
        List<Asset> candidates = tenantSchemaExecutionService.run(tenant, () -> assetRepository.findAll()).stream()
                .filter(a -> "aws".equals(a.getCloudProvider()))
                .filter(a -> awsAccountId.equals(a.getCloudAccountId()))
                .filter(a -> observedScopes.contains(scopeFor(a.getCloudResourceType(), a.getCloudRegion())))
                .filter(a -> a.getLastCmdbSyncAt() != null && a.getLastCmdbSyncAt().isBefore(runStartTime))
                .filter(a -> a.getState() != AssetState.DECOMMISSIONED)
                .filter(a -> !seenResourceIdentifiers.contains(a.getIdentifier()))
                .toList();

        for (Asset stale : candidates) {
            stale.setState(AssetState.INACTIVE);
            assetRepository.save(stale);
        }
        if (!candidates.isEmpty()) {
            LOG.info("Marked {} stale AWS assets as INACTIVE (account={}, runStart={})",
                    candidates.size(), awsAccountId, runStartTime);
        }
        return candidates.size();
    }

    private Optional<Asset> findExistingCloudAsset(
            Tenant tenant,
            AwsResourceRecord record,
            String resourceIdentifier
    ) {
        Optional<Asset> exact = tenantSchemaExecutionService.run(tenant, () -> assetRepository.findByIdentifier(resourceIdentifier));
        if (exact.isPresent() || !hasText(record.arn()) || resourceIdentifier.equals(record.arn())) {
            return exact;
        }
        return tenantSchemaExecutionService.run(tenant, () -> assetRepository.findByIdentifier(record.arn()));
    }

    private String canonicalResourceIdentifier(AwsResourceRecord record, String fallbackAccountId) {
        if (record == null || !hasText(record.arn())) {
            return "";
        }
        if (!"EC2".equalsIgnoreCase(record.resourceType())) {
            return record.arn();
        }
        String accountId = hasText(record.accountId()) ? record.accountId().trim() : trimToNull(fallbackAccountId);
        if (!hasText(accountId)) {
            return record.arn();
        }
        String instanceId = extractInstanceId(record.arn());
        if (!hasText(instanceId)) {
            return record.arn();
        }
        String[] parts = record.arn().split(":", -1);
        String partition = parts.length > 1 && hasText(parts[1]) ? parts[1] : "aws";
        String region = hasText(record.region()) ? record.region().trim()
                : (parts.length > 3 && hasText(parts[3]) ? parts[3] : "");
        return "arn:" + partition + ":ec2:" + region + ":" + accountId + ":instance/" + instanceId;
    }

    private CloudScope scopeFor(String resourceType, String region) {
        return new CloudScope(normalizeScopeValue(resourceType), normalizeScopeValue(region));
    }

    private String normalizeScopeValue(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    // ── Mapping helpers ───────────────────────────────────────────────────────────────────────────

    private AssetState mapState(String cloudState) {
        if (cloudState == null) return AssetState.ACTIVE;
        return switch (cloudState.toLowerCase(Locale.ROOT)) {
            case "running", "available", "active", "in-service" -> AssetState.ACTIVE;
            case "stopped", "stopping", "inactive", "paused", "hibernated" -> AssetState.INACTIVE;
            case "terminated", "deleted", "deleting", "failed" -> AssetState.DECOMMISSIONED;
            default -> AssetState.ACTIVE;
        };
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private Instant parseInstant(String value) {
        if (!hasText(value)) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            return null;
        }
    }

    // ── Inner types ───────────────────────────────────────────────────────────────────────────────

    private record CloudScope(
            String resourceType,
            String region
    ) {}

    private record SsmPackageFetch(
            List<Map<String, String>> rows,
            Instant captureTime
    ) {}
}
