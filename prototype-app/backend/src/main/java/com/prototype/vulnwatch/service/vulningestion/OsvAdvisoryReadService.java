package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class OsvAdvisoryReadService {
    private final OsvAdvisoryRepository repository;

    @Transactional(readOnly = true)
    public List<OsvAdvisoryEntity> findByPackage(String ecosystem, String packageName) {
        return repository.findByEcosystemAndPackageName(ecosystem, packageName);
    }

    @Transactional(readOnly = true)
    public Coverage coverage() {
        Map<String, Long> ecosystemCounts = new HashMap<>();
        for (String ecosystem : List.of("npm", "Python", "Go", "Rust", "RubyGems")) {
            long count = repository.countByEcosystem(ecosystem);
            if (count > 0) {
                ecosystemCounts.put(ecosystem, count);
            }
        }
        Instant lastSyncTime = repository.findAll().stream()
                .map(OsvAdvisoryEntity::getSyncedAt)
                .filter(value -> value != null)
                .max(Instant::compareTo)
                .orElse(null);
        return new Coverage(ecosystemCounts, repository.count(), lastSyncTime);
    }

    public record Coverage(Map<String, Long> ecosystemCounts, long totalAdvisories, Instant lastSyncedAt) { }
}
