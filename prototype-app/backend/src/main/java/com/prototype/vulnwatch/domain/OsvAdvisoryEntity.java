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
    name = "osv_advisories",
    indexes = {
      @Index(name = "idx_osv_ecosystem_package", columnList = "ecosystem,package_name"),
      @Index(name = "idx_osv_package_name", columnList = "package_name"),
      @Index(name = "idx_osv_modified", columnList = "modified_at DESC"),
      @Index(name = "idx_osv_source", columnList = "source")
    })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OsvAdvisoryEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private UUID id;

  @Column(unique = true, nullable = false)
  private String osvId;

  @Column(nullable = false)
  private String ecosystem;

  @Column(nullable = false, length = 500)
  private String packageName;

  @Column(nullable = false, columnDefinition = "TEXT")
  private String summary;

  @Column(columnDefinition = "TEXT")
  private String details;

  private String severity;

  private BigDecimal cvssV3Score;

  private String cvssV3Vector;

  @Column(columnDefinition = "JSONB", nullable = false)
  private String affectedRanges;

  private Instant publishedAt;

  private Instant modifiedAt;

  private Instant withdrawnAt;

  @Column(columnDefinition = "JSONB")
  private String references;

  @Column(columnDefinition = "JSONB", nullable = false)
  private String osvData;

  @Column(nullable = false)
  private String source;

  @CreationTimestamp
  private Instant createdAt;

  @UpdateTimestamp
  private Instant updatedAt;

  private Instant syncedAt;
}
