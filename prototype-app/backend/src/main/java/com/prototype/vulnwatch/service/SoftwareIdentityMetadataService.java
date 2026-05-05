package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SoftwareIdentityMetadataRequest;
import com.prototype.vulnwatch.dto.SoftwareIdentityMetadataResponse;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class SoftwareIdentityMetadataService {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final SoftwareIdentitySummaryProjectionService projectionService;

    public SoftwareIdentityMetadataService(
            NamedParameterJdbcTemplate jdbcTemplate,
            SoftwareIdentitySummaryProjectionService projectionService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.projectionService = projectionService;
    }

    public SoftwareIdentityMetadataResponse getMetadata(Tenant tenant, UUID softwareIdentityId) {
        requireTenant(tenant);
        requireActiveSoftwareIdentity(tenant, softwareIdentityId);
        MapSqlParameterSource params = params(tenant, softwareIdentityId);
        SoftwareIdentityMetadataResponse existing = jdbcTemplate.query("""
                SELECT software_identity_id,
                       owner,
                       licensed,
                       license_type,
                       support_group,
                       recommendation,
                       recommendation_updated_at,
                       updated_at
                FROM software_identity_metadata
                WHERE tenant_id = :tenantId
                  AND software_identity_id = :softwareIdentityId
                """, params, rs -> rs.next() ? mapResponse(rs) : null);
        return existing == null ? defaultMetadata(softwareIdentityId) : existing;
    }

    public SoftwareIdentityMetadataResponse saveMetadata(
            Tenant tenant,
            UUID softwareIdentityId,
            SoftwareIdentityMetadataRequest request
    ) {
        requireTenant(tenant);
        requireActiveSoftwareIdentity(tenant, softwareIdentityId);
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Software metadata request is required");
        }

        boolean hasRecommendation = normalize(request.recommendation()) != null;
        MapSqlParameterSource params = params(tenant, softwareIdentityId)
                .addValue("owner", normalize(request.owner()))
                .addValue("licensed", normalizeLicensed(request.licensed()))
                .addValue("licenseType", normalize(request.licenseType()))
                .addValue("supportGroup", normalize(request.supportGroup()))
                .addValue("recommendation", normalize(request.recommendation()))
                .addValue("recommendationUpdatedAt", hasRecommendation ? Timestamp.from(Instant.now()) : null);

        return jdbcTemplate.queryForObject("""
                INSERT INTO software_identity_metadata (
                    tenant_id,
                    software_identity_id,
                    owner,
                    licensed,
                    license_type,
                    support_group,
                    recommendation,
                    recommendation_updated_at,
                    updated_at
                )
                VALUES (
                    :tenantId,
                    :softwareIdentityId,
                    :owner,
                    :licensed,
                    :licenseType,
                    :supportGroup,
                    :recommendation,
                    :recommendationUpdatedAt,
                    now()
                )
                ON CONFLICT (tenant_id, software_identity_id) DO UPDATE SET
                    owner = EXCLUDED.owner,
                    licensed = EXCLUDED.licensed,
                    license_type = EXCLUDED.license_type,
                    support_group = EXCLUDED.support_group,
                    recommendation = EXCLUDED.recommendation,
                    recommendation_updated_at = CASE
                        WHEN software_identity_metadata.recommendation IS DISTINCT FROM EXCLUDED.recommendation
                            THEN EXCLUDED.recommendation_updated_at
                        ELSE software_identity_metadata.recommendation_updated_at
                    END,
                    updated_at = now()
                RETURNING software_identity_id,
                          owner,
                          licensed,
                          license_type,
                          support_group,
                          recommendation,
                          recommendation_updated_at,
                          updated_at
                """, params, (rs, rowNum) -> mapResponse(rs));
    }

    private void requireTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tenant is required");
        }
    }

    private void requireActiveSoftwareIdentity(Tenant tenant, UUID softwareIdentityId) {
        if (softwareIdentityId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Software identity id is required");
        }
        projectionService.ensureTenantProjection(tenant);
        MapSqlParameterSource params = params(tenant, softwareIdentityId);
        Boolean exists = jdbcTemplate.queryForObject("""
                SELECT EXISTS (
                    SELECT 1
                    FROM software_identity_summary
                    WHERE tenant_id = :tenantId
                      AND software_identity_id = :softwareIdentityId
                )
                """, params, Boolean.class);
        if (!Boolean.TRUE.equals(exists)) {
            projectionService.refreshTenant(tenant);
            exists = jdbcTemplate.queryForObject("""
                    SELECT EXISTS (
                        SELECT 1
                        FROM software_identity_summary
                        WHERE tenant_id = :tenantId
                          AND software_identity_id = :softwareIdentityId
                    )
                    """, params, Boolean.class);
        }
        if (!Boolean.TRUE.equals(exists)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Software identity not found in active inventory");
        }
    }

    private MapSqlParameterSource params(Tenant tenant, UUID softwareIdentityId) {
        return new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("softwareIdentityId", softwareIdentityId);
    }

    private SoftwareIdentityMetadataResponse defaultMetadata(UUID softwareIdentityId) {
        return new SoftwareIdentityMetadataResponse(
                softwareIdentityId,
                "",
                "Unknown",
                "",
                "",
                "",
                null,
                null
        );
    }

    private SoftwareIdentityMetadataResponse mapResponse(ResultSet rs) throws SQLException {
        return new SoftwareIdentityMetadataResponse(
                rs.getObject("software_identity_id", UUID.class),
                valueOrEmpty(rs.getString("owner")),
                valueOrDefault(rs.getString("licensed"), "Unknown"),
                valueOrEmpty(rs.getString("license_type")),
                valueOrEmpty(rs.getString("support_group")),
                valueOrEmpty(rs.getString("recommendation")),
                getInstant(rs, "recommendation_updated_at"),
                getInstant(rs, "updated_at")
        );
    }

    private Instant getInstant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private String normalize(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String normalizeLicensed(String value) {
        String normalized = normalize(value);
        return normalized == null ? "Unknown" : normalized;
    }

    private String valueOrEmpty(String value) {
        return value == null ? "" : value;
    }

    private String valueOrDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
