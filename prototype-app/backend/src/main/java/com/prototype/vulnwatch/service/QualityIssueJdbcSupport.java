package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class QualityIssueJdbcSupport {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public QualityIssueJdbcSupport(NamedParameterJdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public QualityIssueRecord issue(
            UUID tenantId,
            String domain,
            String issueType,
            String issueKeySuffix,
            String severity,
            String reasonCode,
            String title,
            String sourceObjectType,
            String sourceObjectId,
            String primaryLabel,
            String secondaryLabel,
            UUID assetId,
            UUID componentId,
            UUID syncRunId,
            String assetType,
            String sourceSystem,
            String ecosystem,
            boolean affectsActiveFindings,
            long affectedAssetCount,
            long affectedComponentCount,
            long openFindingCount,
            long openVulnerabilityCount,
            Instant firstSeenAt,
            Instant lastSeenAt,
            Map<String, Object> evidence
    ) {
        return issue(
                tenantId,
                domain,
                issueType,
                issueKeySuffix,
                severity,
                reasonCode,
                title,
                sourceObjectType,
                sourceObjectId,
                primaryLabel,
                secondaryLabel,
                assetId,
                componentId,
                null,
                null,
                syncRunId,
                assetType,
                sourceSystem,
                ecosystem,
                affectsActiveFindings,
                affectedAssetCount,
                affectedComponentCount,
                openFindingCount,
                openVulnerabilityCount,
                firstSeenAt,
                lastSeenAt,
                evidence
        );
    }

    public QualityIssueRecord issue(
            UUID tenantId,
            String domain,
            String issueType,
            String issueKeySuffix,
            String severity,
            String reasonCode,
            String title,
            String sourceObjectType,
            String sourceObjectId,
            String primaryLabel,
            String secondaryLabel,
            UUID assetId,
            UUID componentId,
            UUID softwareIdentityId,
            UUID vulnerabilityId,
            String assetType,
            String sourceSystem,
            String ecosystem,
            boolean affectsActiveFindings,
            long affectedAssetCount,
            long affectedComponentCount,
            long openFindingCount,
            long openVulnerabilityCount,
            Instant firstSeenAt,
            Instant lastSeenAt,
            Map<String, Object> evidence
    ) {
        return issue(
                tenantId,
                domain,
                issueType,
                issueKeySuffix,
                severity,
                reasonCode,
                title,
                sourceObjectType,
                sourceObjectId,
                primaryLabel,
                secondaryLabel,
                assetId,
                componentId,
                softwareIdentityId,
                vulnerabilityId,
                null,
                assetType,
                sourceSystem,
                ecosystem,
                affectsActiveFindings,
                affectedAssetCount,
                affectedComponentCount,
                openFindingCount,
                openVulnerabilityCount,
                firstSeenAt,
                lastSeenAt,
                evidence
        );
    }

    public QualityIssueRecord issue(
            UUID tenantId,
            String domain,
            String issueType,
            String issueKeySuffix,
            String severity,
            String reasonCode,
            String title,
            String sourceObjectType,
            String sourceObjectId,
            String primaryLabel,
            String secondaryLabel,
            UUID assetId,
            UUID componentId,
            UUID softwareIdentityId,
            UUID vulnerabilityId,
            UUID syncRunId,
            String assetType,
            String sourceSystem,
            String ecosystem,
            boolean affectsActiveFindings,
            long affectedAssetCount,
            long affectedComponentCount,
            long openFindingCount,
            long openVulnerabilityCount,
            Instant firstSeenAt,
            Instant lastSeenAt,
            Map<String, Object> evidence
    ) {
        String normalizedDomain = normalizeExact(domain);
        String normalizedIssueType = normalizeExact(issueType);
        String issueKey = normalizedDomain.toLowerCase(Locale.ROOT) + ":" + normalizeForKey(issueKeySuffix);
        String id = tenantId + ":" + issueKey;
        Instant seenAt = firstSeenAt == null ? Instant.now() : firstSeenAt;
        Instant observedAt = lastSeenAt == null ? seenAt : lastSeenAt;
        return new QualityIssueRecord(
                id,
                tenantId,
                issueKey,
                normalizedDomain,
                normalizedIssueType,
                normalizeExact(severity),
                reasonCode,
                sourceObjectType,
                sourceObjectId,
                assetId,
                componentId,
                softwareIdentityId,
                vulnerabilityId,
                syncRunId,
                title,
                primaryLabel,
                secondaryLabel,
                assetType == null ? null : normalizeExact(assetType),
                sourceSystem == null ? null : normalizeSource(sourceSystem),
                ecosystem == null ? null : ecosystem.trim().toLowerCase(Locale.ROOT),
                affectsActiveFindings,
                affectedAssetCount,
                affectedComponentCount,
                openFindingCount,
                openVulnerabilityCount,
                seenAt,
                observedAt,
                Instant.now(),
                toJson(evidence),
                "[]"
        );
    }

    public MapSqlParameterSource tenantParams(UUID tenantId) {
        return new MapSqlParameterSource().addValue("tenantId", tenantId);
    }

    public long queryLong(String sql, MapSqlParameterSource params) {
        Long value = jdbcTemplate.queryForObject(sql, params, Long.class);
        return value == null ? 0L : value;
    }

    public String severityForExposureIssue(long openFindingCount, long openVulnerabilityCount, String defaultSeverity) {
        if (openFindingCount > 0) {
            return "HIGH";
        }
        if (openVulnerabilityCount > 0) {
            return "MEDIUM";
        }
        return defaultSeverity;
    }

    public boolean affectsActiveFindings(long openFindingCount, long openVulnerabilityCount) {
        return openFindingCount > 0 || openVulnerabilityCount > 0;
    }

    public boolean isVulnerabilityOrLifecycleSource(String syncType) {
        String normalized = normalizeSource(syncType);
        return normalized.contains("vex")
                || normalized.contains("csaf")
                || normalized.contains("nvd")
                || normalized.contains("eol");
    }

    public String normalizeSource(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim()
                .toLowerCase(Locale.ROOT)
                .replace(' ', '_')
                .replace('-', '_');
    }

    public String normalizeExact(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }

    public String normalizeForKey(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim()
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
    }

    public String vexPairKey(UUID componentId, UUID vulnerabilityId) {
        if (componentId == null || vulnerabilityId == null) {
            return null;
        }
        return componentId + ":" + vulnerabilityId;
    }

    public String toJson(Map<String, Object> evidence) {
        try {
            return objectMapper.writeValueAsString(evidence == null ? Map.of() : evidence);
        } catch (JsonProcessingException ignored) {
            return "{}";
        }
    }

    public String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    public UUID uuidValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof UUID uuid) {
            return uuid;
        }
        String text = String.valueOf(value).trim();
        if (text.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(text);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    public long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value == null) {
            return 0L;
        }
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return 0L;
        }
    }

    public double doubleValue(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value == null) {
            return 0d;
        }
        try {
            return Double.parseDouble(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return 0d;
        }
    }

    public boolean boolValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value != null && Boolean.parseBoolean(String.valueOf(value));
    }

    public Instant instantValue(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant();
        }
        return null;
    }
}
