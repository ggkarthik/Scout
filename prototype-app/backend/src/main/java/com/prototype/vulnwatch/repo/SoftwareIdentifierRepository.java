package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.IdentifierType;
import com.prototype.vulnwatch.domain.SoftwareIdentifier;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SoftwareIdentifierRepository extends JpaRepository<SoftwareIdentifier, UUID> {
    Optional<SoftwareIdentifier> findBySoftwareIdentityAndIdTypeAndNormalizedValue(
            SoftwareIdentity softwareIdentity,
            IdentifierType idType,
            String normalizedValue
    );

    List<SoftwareIdentifier> findBySoftwareIdentity(SoftwareIdentity softwareIdentity);

    List<SoftwareIdentifier> findByIdTypeAndNormalizedValue(IdentifierType idType, String normalizedValue);
}
