package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.PatchConnectorCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PatchConnectorCredentialRepository extends JpaRepository<PatchConnectorCredential, UUID> {

    @Query("""
        SELECT pcc FROM PatchConnectorCredential pcc
        WHERE pcc.tenantId = :tenantId
        AND pcc.connectorType = :connectorType
        """)
    Optional<PatchConnectorCredential> findByTenantAndConnectorType(
        @Param("tenantId") UUID tenantId,
        @Param("connectorType") String connectorType
    );

    @Query("""
        SELECT pcc FROM PatchConnectorCredential pcc
        WHERE pcc.connectorType = :connectorType
        AND pcc.tenantId IS NULL
        """)
    Optional<PatchConnectorCredential> findPlatformCredentialByConnectorType(
        @Param("connectorType") String connectorType
    );

    @Query("""
        SELECT pcc FROM PatchConnectorCredential pcc
        WHERE pcc.connectorType = :connectorType
        """)
    List<PatchConnectorCredential> findByConnectorType(
        @Param("connectorType") String connectorType
    );
}
