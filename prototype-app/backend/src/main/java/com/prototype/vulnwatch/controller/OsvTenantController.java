package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.service.vulningestion.OsvAdvisoryReadService;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tenants/{tenantId}/osv")
@RequiredArgsConstructor
@Slf4j
public class OsvTenantController {

  private final OsvAdvisoryReadService readService;

  @GetMapping("/component-advisories")
  @PreAuthorize("hasAnyRole('TENANT_ADMIN', 'INVENTORY_ADMIN', 'SECURITY_ANALYST')")
  public List<OsvAdvisoryResponse> getComponentAdvisories(
      @PathVariable UUID tenantId,
      @RequestParam String ecosystem,
      @RequestParam String packageName,
      Pageable pageable) {

    log.debug("Fetching OSV advisories for {}:{}", ecosystem, packageName);

    List<OsvAdvisoryEntity> advisories =
        readService.findByPackage(ecosystem, packageName);

    return advisories.stream().map(this::toResponse).collect(Collectors.toList());
  }

  @GetMapping("/coverage")
  @PreAuthorize("hasAnyRole('TENANT_ADMIN', 'INVENTORY_ADMIN', 'SECURITY_ANALYST')")
  public OsvCoverageResponse getCoverage(@PathVariable UUID tenantId) {
    OsvAdvisoryReadService.Coverage coverage = readService.coverage();
    return OsvCoverageResponse.builder()
        .ecosystemCounts(coverage.ecosystemCounts())
        .totalAdvisories(coverage.totalAdvisories())
        .lastSyncedAt(coverage.lastSyncedAt())
        .build();
  }

  private OsvAdvisoryResponse toResponse(OsvAdvisoryEntity entity) {
    return OsvAdvisoryResponse.builder()
        .osvId(entity.getOsvId())
        .ecosystem(entity.getEcosystem())
        .packageName(entity.getPackageName())
        .summary(entity.getSummary())
        .severity(entity.getSeverity())
        .cvssV3Score(entity.getCvssV3Score())
        .publishedAt(entity.getPublishedAt())
        .modifiedAt(entity.getModifiedAt())
        .source(entity.getSource())
        .build();
  }

  // DTOs

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvAdvisoryResponse {
    private String osvId;
    private String ecosystem;
    private String packageName;
    private String summary;
    private String severity;
    private BigDecimal cvssV3Score;
    private Instant publishedAt;
    private Instant modifiedAt;
    private String source;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OsvCoverageResponse {
    private Map<String, Long> ecosystemCounts;
    private long totalAdvisories;
    private Instant lastSyncedAt;
  }
}
