package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.IdentityLink;
import com.prototype.vulnwatch.domain.SoftwareIdentifier;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IdentityLinkRepository extends JpaRepository<IdentityLink, UUID> {
    Optional<IdentityLink> findByFromIdentifierAndToIdentifierAndLinkTypeAndSource(
            SoftwareIdentifier fromIdentifier,
            SoftwareIdentifier toIdentifier,
            String linkType,
            String source
    );
}
