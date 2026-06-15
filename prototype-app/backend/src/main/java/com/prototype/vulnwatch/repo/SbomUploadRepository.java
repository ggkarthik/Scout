package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.SbomUpload;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SbomUploadRepository extends JpaRepository<SbomUpload, UUID> {
    List<SbomUpload> findByAssetOrderByUploadedAtDesc(Asset asset);
    List<SbomUpload> findAllByOrderByUploadedAtDesc();
    List<SbomUpload> findByIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc(String ingestionSourceSystem);
    List<SbomUpload> findByUploadedAtGreaterThanEqualOrderByUploadedAtDesc(Instant fromInclusive);
    Page<SbomUpload> findAllByOrderByUploadedAtDesc(Pageable pageable);
    Page<SbomUpload> findByIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc(String ingestionSourceSystem, Pageable pageable);
    long countByUploadedAtGreaterThanEqual(Instant fromInclusive);
}
