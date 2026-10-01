package com.prototype.vulnwatch.domain;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
    name = "advisory_equivalences",
    schema = "platform",
    indexes = {
      @Index(name = "idx_advisory_equivalences_cve", columnList = "nvd_cve_id"),
      @Index(name = "idx_advisory_equivalences_ghsa", columnList = "ghsa_id"),
      @Index(name = "idx_advisory_equivalences_osv", columnList = "osv_id")
    })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdvisoryEquivalenceEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private UUID id;

  private String nvdCveId;

  private String ghsaId;

  private String osvId;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "JSONB")
  private String cweIds;

  private BigDecimal equivalenceConfidence;

  private String equivalenceReason;

  private Instant discoveredAt;

  private Instant verifiedAt;

  private UUID verifiedByUserId;

  @Column(columnDefinition = "TEXT")
  private String notes;

  @CreationTimestamp
  private Instant createdAt;

  @UpdateTimestamp
  private Instant updatedAt;
}
