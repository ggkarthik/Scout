package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OrgCveRecordService {

    private static final int REFRESH_BATCH_SIZE = 500;
    private static final String REASON_NOT_APPLICABLE = "no_supported_match_in_software_inventory";
    private static final String REASON_AWAITING_VEX = "awaiting_vex_assessment";
    private static final String REASON_VEX_NO_PATCH = "vex_no_patch";
    private static final String REASON_VEX_AFFECTED = "vex_affected_or_untriaged";
    private static final String REASON_VEX_UNDER_INVESTIGATION = "vex_under_investigation";
    private static final String REASON_VEX_FIXED = "vex_fixed";
    private static final String REASON_VEX_NOT_AFFECTED = "vex_not_affected";

    private final OrgCveRecordRepository orgCveRecordRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final TenantRepository tenantRepository;

    public OrgCveRecordService(
            OrgCveRecordRepository orgCveRecordRepository,
            VulnerabilityRepository vulnerabilityRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            TenantRepository tenantRepository
    ) {
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.tenantRepository = tenantRepository;
    }

    @Transactional
    public int refreshForAllTenants(UUID vulnerabilityId) {
        if (vulnerabilityId == null) {
            return 0;
        }
        int updated = 0;
        List<Tenant> tenants = tenantRepository.findAllByOrderByCreatedAtAsc();
        for (Tenant tenant : tenants) {
            updated += refreshForTenantAndVulnerabilities(tenant, List.of(vulnerabilityId));
        }
        return updated;
    }

    @Transactional
    public int refreshForTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return 0;
        }

        List<UUID> vulnerabilityIds = vulnerabilityRepository.findAllIdsOrderedForOrgExposureRefresh();
        if (vulnerabilityIds.isEmpty()) {
            return 0;
        }

        int updated = 0;
        for (int offset = 0; offset < vulnerabilityIds.size(); offset += REFRESH_BATCH_SIZE) {
            int end = Math.min(offset + REFRESH_BATCH_SIZE, vulnerabilityIds.size());
            updated += refreshForTenantAndVulnerabilities(tenant, vulnerabilityIds.subList(offset, end));
        }
        return updated;
    }

    @Transactional
    public int refreshForTenantAndVulnerabilities(UUID tenantId, Collection<UUID> vulnerabilityIds) {
        if (tenantId == null || vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        return tenantRepository.findById(tenantId)
                .map(tenant -> refreshForTenantAndVulnerabilities(tenant, vulnerabilityIds))
                .orElse(0);
    }

    @Transactional
    public int refreshForTenantAndVulnerabilities(Tenant tenant, Collection<UUID> vulnerabilityIds) {
        if (tenant == null || tenant.getId() == null || vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }

        List<UUID> scopedVulnerabilityIds = vulnerabilityIds.stream()
                .filter(Objects::nonNull)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .sorted(UUID::compareTo)
                .toList();
        if (scopedVulnerabilityIds.isEmpty()) {
            return 0;
        }

        Map<UUID, Vulnerability> vulnerabilitiesById = vulnerabilityRepository.findAllById(scopedVulnerabilityIds).stream()
                .filter(vulnerability -> vulnerability.getId() != null)
                .collect(java.util.stream.Collectors.toMap(
                        Vulnerability::getId,
                        vulnerability -> vulnerability,
                        (left, right) -> left,
                        LinkedHashMap::new
                ));
        if (vulnerabilitiesById.isEmpty()) {
            return 0;
        }

        List<UUID> existingVulnerabilityIds = vulnerabilitiesById.keySet().stream()
                .sorted(Comparator.naturalOrder())
                .toList();

        Map<UUID, OrgCveRecord> existingByVulnerability = new HashMap<>();
        orgCveRecordRepository.findByTenantAndVulnerability_IdIn(tenant, existingVulnerabilityIds).forEach(record -> {
            if (record.getVulnerability() != null && record.getVulnerability().getId() != null) {
                existingByVulnerability.put(record.getVulnerability().getId(), record);
            }
        });

        // Determine applicability from ComponentVulnerabilityState — covers CPE, PURL, COORD,
        // and ADVISORY_PACKAGE matches equally, and only counts ACTIVE components (G4 + G11).
        Set<UUID> applicableVulnerabilityIds =
                componentVulnerabilityStateRepository.findApplicableVulnerabilityIdsByTenantAndVulnerabilityIds(
                        tenant,
                        existingVulnerabilityIds
                );

        Map<UUID, ComponentVulnerabilityStateRepository.VulnerabilityImpactAggregateRow> impactByVulnerability = new HashMap<>();
        componentVulnerabilityStateRepository
                .findImpactAggregatesByTenantIdAndVulnerabilityIds(tenant.getId(), existingVulnerabilityIds)
                .forEach(row -> {
                    if (row.getVulnerabilityId() != null) {
                        impactByVulnerability.put(row.getVulnerabilityId(), row);
                    }
                });

        Instant now = Instant.now();
        List<OrgCveRecord> toSave = new ArrayList<>();
        for (UUID vulnerabilityId : existingVulnerabilityIds) {
            Vulnerability vulnerability = vulnerabilitiesById.get(vulnerabilityId);
            if (vulnerability == null) {
                continue;
            }

            boolean applicable = applicableVulnerabilityIds.contains(vulnerabilityId);
            ApplicabilityState applicabilityState =
                    applicable ? ApplicabilityState.APPLICABLE : ApplicabilityState.NOT_APPLICABLE;
            ComponentVulnerabilityStateRepository.VulnerabilityImpactAggregateRow agg =
                    impactByVulnerability.get(vulnerabilityId);
            long matchedComponentCount = agg == null ? 0
                    : agg.getNoPatchCount() + agg.getImpactedCount() + agg.getUnknownCount()
                    + agg.getFixedCount() + agg.getNotImpactedCount();
            long matchedSoftwareCount = applicable ? matchedComponentCount : 0;
            ImpactSummary impactSummary = resolveImpact(
                    applicabilityState,
                    impactByVulnerability.get(vulnerabilityId)
            );
            OrgCveSnapshot snapshot = new OrgCveSnapshot(
                    resolveExternalId(vulnerability),
                    normalizeSeverity(vulnerability.getSeverity()),
                    vulnerability.getCvssScore(),
                    vulnerability.getEpssScore(),
                    vulnerability.isInKev(),
                    hasText(vulnerability.getVulnStatus()) ? vulnerability.getVulnStatus().trim() : null,
                    applicabilityState,
                    impactSummary.impacted(),
                    impactSummary.impactState(),
                    impactSummary.impactReason(),
                    matchedComponentCount,
                    matchedSoftwareCount
            );

            OrgCveRecord record = existingByVulnerability.get(vulnerabilityId);
            boolean created = false;
            if (record == null) {
                record = new OrgCveRecord();
                record.setTenant(tenant);
                record.setVulnerability(vulnerability);
                created = true;
            }

            boolean changed = applySnapshot(record, snapshot);
            if (created) {
                changed = true;
            }
            if (!changed) {
                continue;
            }

            record.setLastEvaluatedAt(now);
            record.touch();
            toSave.add(record);
        }

        if (!toSave.isEmpty()) {
            orgCveRecordRepository.saveAll(toSave);
        }
        return toSave.size();
    }

    @Transactional(readOnly = true)
    public boolean isActivelySuppressed(Tenant tenant, Vulnerability vulnerability, Instant at) {
        if (tenant == null || tenant.getId() == null || vulnerability == null) {
            return false;
        }
        return orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .map(record -> record.isActivelySuppressed(at))
                .orElse(false);
    }

    @Transactional
    public OrgCveRecord suppress(
            Tenant tenant,
            Vulnerability vulnerability,
            String reason,
            String justification,
            String suppressedBy,
            Instant suppressedAt,
            Instant suppressedUntil
    ) {
        if (tenant == null || tenant.getId() == null || vulnerability == null) {
            throw new IllegalArgumentException("Tenant and vulnerability are required");
        }
        Instant now = suppressedAt == null ? Instant.now() : suppressedAt;
        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElseGet(() -> initializeRecord(tenant, vulnerability, now));
        record.setSuppressionReason(trimToNull(reason));
        record.setSuppressionJustification(trimToNull(justification));
        record.setSuppressedBy(trimToNull(suppressedBy));
        record.setSuppressedAt(now);
        record.setSuppressedUntil(suppressedUntil);
        if (record.getLastEvaluatedAt() == null) {
            record.setLastEvaluatedAt(now);
        }
        record.touch();
        return orgCveRecordRepository.save(record);
    }

    private boolean applySnapshot(OrgCveRecord record, OrgCveSnapshot snapshot) {
        boolean changed = false;
        changed |= setIfChanged(record.getExternalId(), snapshot.externalId(), record::setExternalId);
        changed |= setIfChanged(record.getSeverity(), snapshot.severity(), record::setSeverity);
        changed |= setIfChanged(record.getCvssScore(), snapshot.cvssScore(), record::setCvssScore);
        changed |= setIfChanged(record.getEpssScore(), snapshot.epssScore(), record::setEpssScore);
        changed |= setIfChanged(record.isInKev(), snapshot.inKev(), record::setInKev);
        changed |= setIfChanged(record.getVulnStatus(), snapshot.vulnStatus(), record::setVulnStatus);
        changed |= setIfChanged(record.getApplicabilityState(), snapshot.applicabilityState(), record::setApplicabilityState);
        changed |= setIfChanged(record.isImpacted(), snapshot.impacted(), record::setImpacted);
        changed |= setIfChanged(record.getImpactState(), snapshot.impactState(), record::setImpactState);
        changed |= setIfChanged(record.getImpactReason(), snapshot.impactReason(), record::setImpactReason);
        changed |= setIfChanged(record.getMatchedComponentCount(), snapshot.matchedComponentCount(), record::setMatchedComponentCount);
        changed |= setIfChanged(record.getMatchedSoftwareCount(), snapshot.matchedSoftwareCount(), record::setMatchedSoftwareCount);
        return changed;
    }

    private OrgCveRecord initializeRecord(Tenant tenant, Vulnerability vulnerability, Instant now) {
        OrgCveRecord record = new OrgCveRecord();
        record.setTenant(tenant);
        record.setVulnerability(vulnerability);
        record.setExternalId(resolveExternalId(vulnerability));
        record.setSeverity(normalizeSeverity(vulnerability.getSeverity()));
        record.setCvssScore(vulnerability.getCvssScore());
        record.setEpssScore(vulnerability.getEpssScore());
        record.setInKev(vulnerability.isInKev());
        record.setVulnStatus(hasText(vulnerability.getVulnStatus()) ? vulnerability.getVulnStatus().trim() : null);
        record.setApplicabilityState(ApplicabilityState.UNKNOWN);
        record.setImpacted(false);
        record.setImpactState(ImpactState.UNKNOWN);
        record.setImpactReason("suppressed_before_evaluation");
        record.setMatchedComponentCount(0);
        record.setMatchedSoftwareCount(0);
        record.setLastEvaluatedAt(now);
        record.touch();
        return record;
    }

    private ImpactSummary resolveImpact(
            ApplicabilityState applicabilityState,
            ComponentVulnerabilityStateRepository.VulnerabilityImpactAggregateRow impactAggregate
    ) {
        if (applicabilityState != ApplicabilityState.APPLICABLE) {
            return new ImpactSummary(ImpactState.NOT_IMPACTED, false, REASON_NOT_APPLICABLE);
        }
        if (impactAggregate == null) {
            return new ImpactSummary(ImpactState.UNKNOWN, false, REASON_AWAITING_VEX);
        }
        if (impactAggregate.getNoPatchCount() > 0) {
            return new ImpactSummary(ImpactState.NO_PATCH, true, REASON_VEX_NO_PATCH);
        }
        if (impactAggregate.getImpactedCount() > 0) {
            return new ImpactSummary(ImpactState.IMPACTED, true, REASON_VEX_AFFECTED);
        }
        if (impactAggregate.getUnknownCount() > 0) {
            return new ImpactSummary(ImpactState.UNKNOWN, false, REASON_VEX_UNDER_INVESTIGATION);
        }
        if (impactAggregate.getFixedCount() > 0) {
            return new ImpactSummary(ImpactState.FIXED, false, REASON_VEX_FIXED);
        }
        if (impactAggregate.getNotImpactedCount() > 0) {
            return new ImpactSummary(ImpactState.NOT_IMPACTED, false, REASON_VEX_NOT_AFFECTED);
        }
        return new ImpactSummary(ImpactState.UNKNOWN, false, REASON_AWAITING_VEX);
    }

    private String normalizeSeverity(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN";
        }
        return value.trim().toUpperCase(Locale.ROOT);
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

    private String resolveExternalId(Vulnerability vulnerability) {
        if (vulnerability != null && hasText(vulnerability.getExternalId())) {
            return vulnerability.getExternalId().trim().toUpperCase(Locale.ROOT);
        }
        if (vulnerability != null && vulnerability.getId() != null) {
            return "VULN-" + vulnerability.getId();
        }
        return "VULN-UNKNOWN";
    }

    private <T> boolean setIfChanged(T current, T next, Consumer<T> setter) {
        if (Objects.equals(current, next)) {
            return false;
        }
        setter.accept(next);
        return true;
    }

    private record ImpactSummary(
            ImpactState impactState,
            boolean impacted,
            String impactReason
    ) {
    }

    private record OrgCveSnapshot(
            String externalId,
            String severity,
            Double cvssScore,
            Double epssScore,
            boolean inKev,
            String vulnStatus,
            ApplicabilityState applicabilityState,
            boolean impacted,
            ImpactState impactState,
            String impactReason,
            long matchedComponentCount,
            long matchedSoftwareCount
    ) {
    }
}
