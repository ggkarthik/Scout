package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SbomUploadRepository extends JpaRepository<SbomUpload, UUID> {
    List<SbomUpload> findByAssetOrderByUploadedAtDesc(Asset asset);
    List<SbomUpload> findByTenantOrderByUploadedAtDesc(Tenant tenant);
    List<SbomUpload> findByTenantAndUploadedAtGreaterThanEqualOrderByUploadedAtDesc(Tenant tenant, Instant fromInclusive);
}
