package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.domain.AdvisoryEquivalenceEntity;
import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.repo.AdvisoryEquivalenceRepository;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AdvisoryDeduplicationService {

  private final AdvisoryEquivalenceRepository equivalenceRepository;
  private final OsvAdvisoryRepository osvAdvisoryRepository;

  @Transactional(readOnly = true)
  public AdvisoryEquivalenceGroup getEquivalentAdvisories(String cveId) {
    List<AdvisoryEquivalenceEntity> equivalences = equivalenceRepository.findByNvdCveId(cveId);

    AdvisoryEquivalenceGroup group = AdvisoryEquivalenceGroup.builder()
        .primaryCveId(cveId)
        .ghsaIds(new HashSet<>())
        .osvIds(new HashSet<>())
        .build();

    for (AdvisoryEquivalenceEntity eq : equivalences) {
      if (eq.getGhsaId() != null) {
        group.getGhsaIds().add(eq.getGhsaId());
      }
      if (eq.getOsvId() != null) {
        group.getOsvIds().add(eq.getOsvId());
      }
    }

    return group;
  }

  @Transactional(readOnly = true)
  public Optional<OsvAdvisoryEntity> findEquivalentOsvAdvisory(String cveId) {
    List<AdvisoryEquivalenceEntity> equivalences = equivalenceRepository.findByNvdCveId(cveId);

    for (AdvisoryEquivalenceEntity eq : equivalences) {
      if (eq.getOsvId() != null) {
        return osvAdvisoryRepository.findByOsvId(eq.getOsvId());
      }
    }

    return Optional.empty();
  }

  @Transactional(readOnly = true)
  public Set<String> getEquivalentGhsaIds(String cveId) {
    AdvisoryEquivalenceGroup group = getEquivalentAdvisories(cveId);
    return group.getGhsaIds();
  }

  @Data
  @Builder
  public static class AdvisoryEquivalenceGroup {
    private String primaryCveId;
    private Set<String> ghsaIds;
    private Set<String> osvIds;
  }
}
