package com.prototype.vulnwatch.domain;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(
    name = "advisory_equivalences",
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
