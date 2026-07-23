package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DemoDatasetProvisioningService {

    private static final Logger LOG = LoggerFactory.getLogger(DemoDatasetProvisioningService.class);
    public static final String REQUESTED_MARKER = "CUSTOMER_DATASET_REQUESTED";
    public static final String SEEDING_MARKER = "CUSTOMER_DATASET_SEEDING";
    public static final String SEEDED_MARKER = "CUSTOMER_DATASET_V1_SEEDED";

    private final TenantRepository tenantRepository;
    private final JdbcTemplate jdbcTemplate;
    private final CustomerDemoDatasetService datasetService;

    public DemoDatasetProvisioningService(
            TenantRepository tenantRepository,
            JdbcTemplate jdbcTemplate,
            CustomerDemoDatasetService datasetService
    ) {
        this.tenantRepository = tenantRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.datasetService = datasetService;
    }

    @Transactional
    public Tenant request(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenant.setDemoSource(REQUESTED_MARKER);
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }

    public CustomerDemoDatasetService.DemoDatasetSummary requestAndSeed(UUID tenantId) {
        request(tenantId);
        return seedIfReady(tenantId);
    }

    @Scheduled(initialDelayString = "${app.demo-data.initial-delay-ms:15000}",
            fixedDelayString = "${app.demo-data.poll-delay-ms:30000}")
    public void seedRequestedTenants() {
        tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                .filter(DemoDatasetProvisioningService::isRequested)
                .filter(tenant -> "ACTIVE".equalsIgnoreCase(tenant.getStatus()))
                .forEach(tenant -> {
                    try {
                        seedIfReady(tenant.getId());
                    } catch (RuntimeException ex) {
                        LOG.error("Demo dataset seed failed for tenant {}", tenant.getId(), ex);
                    }
                });
    }

    public CustomerDemoDatasetService.DemoDatasetSummary seedIfReady(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        if (!"ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
            throw new IllegalStateException("Tenant must be ACTIVE before demo data can be seeded");
        }
        int claimed = jdbcTemplate.update("""
                UPDATE platform.tenants
                   SET demo_source = ?,
                       updated_at = now()
                 WHERE id = ?
                   AND coalesce(demo_source, '') <> ?
                """, SEEDING_MARKER, tenantId, SEEDING_MARKER);
        if (claimed == 0) {
            throw new IllegalStateException("Demo data seed is already running");
        }
        try {
            CustomerDemoDatasetService.DemoDatasetSummary summary = datasetService.seed(tenant);
            jdbcTemplate.update("""
                    UPDATE platform.tenants
                       SET demo_source = ?,
                           updated_at = now()
                     WHERE id = ?
                    """, SEEDED_MARKER, tenantId);
            return summary;
        } catch (RuntimeException ex) {
            jdbcTemplate.update("""
                    UPDATE platform.tenants
                       SET demo_source = ?,
                           updated_at = now()
                     WHERE id = ?
                    """, REQUESTED_MARKER, tenantId);
            throw ex;
        }
    }

    public static boolean isRequested(Tenant tenant) {
        String source = tenant.getDemoSource();
        return REQUESTED_MARKER.equals(source) || SEEDING_MARKER.equals(source) || SEEDED_MARKER.equals(source);
    }

    public static String status(Tenant tenant) {
        return switch (tenant.getDemoSource() == null ? "" : tenant.getDemoSource()) {
            case REQUESTED_MARKER -> "REQUESTED";
            case SEEDING_MARKER -> "SEEDING";
            case SEEDED_MARKER -> "SEEDED";
            default -> "NOT_REQUESTED";
        };
    }

    public static String version(Tenant tenant) {
        return SEEDED_MARKER.equals(tenant.getDemoSource()) ? CustomerDemoDatasetService.DATASET_VERSION : null;
    }
}
