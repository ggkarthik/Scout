package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.repo.CpeDimRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CpeDimensionService {

    private final CpeDimRepository cpeDimRepository;

    public CpeDimensionService(CpeDimRepository cpeDimRepository) {
        this.cpeDimRepository = cpeDimRepository;
    }

    @Transactional
    public CpeDim resolveOrCreate(String rawCpe) {
        Map<String, String> rawByNormalized = normalizeRawCpes(List.of(rawCpe));
        if (rawByNormalized.isEmpty()) {
            return null;
        }
        return resolveOrCreateAllInternal(rawByNormalized).values().stream().findFirst().orElse(null);
    }

    @Transactional
    public List<CpeDim> resolveOrCreateAll(Collection<String> rawCpes) {
        Map<String, String> rawByNormalized = normalizeRawCpes(rawCpes);
        if (rawByNormalized.isEmpty()) {
            return List.of();
        }
        return resolveOrCreateAllInternal(rawByNormalized).values().stream()
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    @Transactional
    public Map<String, CpeDim> resolveOrCreateAllByNormalizedCpe(Collection<String> normalizedCpes) {
        if (normalizedCpes == null || normalizedCpes.isEmpty()) {
            return Map.of();
        }
        Map<String, String> rawByNormalized = new LinkedHashMap<>();
        for (String normalizedCpe : normalizedCpes) {
            if (normalizedCpe == null || normalizedCpe.isBlank()) {
                continue;
            }
            String normalized = CpeUtil.normalizeCpe23(normalizedCpe);
            if (normalized != null) {
                rawByNormalized.putIfAbsent(normalized, normalized);
            }
        }
        if (rawByNormalized.isEmpty()) {
            return Map.of();
        }
        return resolveOrCreateAllInternal(rawByNormalized);
    }

    private Map<String, String> normalizeRawCpes(Collection<String> rawCpes) {
        if (rawCpes == null || rawCpes.isEmpty()) {
            return Map.of();
        }
        Map<String, String> rawByNormalized = new LinkedHashMap<>();
        for (String rawCpe : rawCpes) {
            if (rawCpe == null || rawCpe.isBlank()) {
                continue;
            }
            String trimmed = rawCpe.trim();
            String normalized = CpeUtil.normalizeCpe23(trimmed);
            if (normalized != null) {
                rawByNormalized.putIfAbsent(normalized, trimmed);
            }
        }
        return rawByNormalized;
    }

    private Map<String, CpeDim> resolveOrCreateAllInternal(Map<String, String> rawByNormalized) {
        Map<String, CpeDim> resolvedByNormalized = new LinkedHashMap<>();
        List<CpeDim> existingRows = cpeDimRepository.findAllByNormalizedCpeIn(rawByNormalized.keySet());
        List<CpeDim> existingToSave = new ArrayList<>();
        for (CpeDim existing : existingRows) {
            String normalized = existing.getNormalizedCpe();
            if (normalized == null || normalized.isBlank()) {
                continue;
            }
            String rawCpe = rawByNormalized.get(normalized);
            if (rawCpe == null) {
                continue;
            }
            existing.setRawCpe(rawCpe);
            existing.touch();
            existingToSave.add(existing);
            resolvedByNormalized.put(normalized, existing);
        }
        if (!existingToSave.isEmpty()) {
            cpeDimRepository.saveAll(existingToSave);
        }

        List<CpeDim> missingRows = new ArrayList<>();
        for (Map.Entry<String, String> entry : rawByNormalized.entrySet()) {
            if (resolvedByNormalized.containsKey(entry.getKey())) {
                continue;
            }
            missingRows.add(buildDimension(entry.getValue(), entry.getKey()));
        }

        if (!missingRows.isEmpty()) {
            try {
                for (CpeDim saved : cpeDimRepository.saveAll(missingRows)) {
                    resolvedByNormalized.put(saved.getNormalizedCpe(), saved);
                }
            } catch (DataIntegrityViolationException race) {
                List<CpeDim> refetched = cpeDimRepository.findAllByNormalizedCpeIn(rawByNormalized.keySet());
                for (CpeDim existing : refetched) {
                    resolvedByNormalized.put(existing.getNormalizedCpe(), existing);
                }
            }
        }

        Map<String, CpeDim> ordered = new LinkedHashMap<>();
        for (String normalized : rawByNormalized.keySet()) {
            CpeDim dim = resolvedByNormalized.get(normalized);
            if (dim != null) {
                ordered.put(normalized, dim);
            }
        }
        return ordered;
    }

    private CpeDim buildDimension(String rawCpe, String normalized) {
        CpeUtil.ParsedCpe parsed = CpeUtil.parse(normalized);
        CpeDim dim = new CpeDim();
        dim.setRawCpe(rawCpe.trim());
        dim.setNormalizedCpe(normalized);
        dim.setPart(token(parsed.part()));
        dim.setVendor(token(parsed.vendor()));
        dim.setProduct(token(parsed.product()));
        dim.setVersion(token(parsed.version()));
        dim.setUpdate(token(parsed.update()));
        dim.setEdition(token(parsed.edition()));
        dim.setLanguage(token(parsed.language()));
        dim.setSwEdition(token(parsed.swEdition()));
        dim.setTargetSw(token(parsed.targetSw()));
        dim.setTargetHw(token(parsed.targetHw()));
        dim.setOther(token(parsed.other()));
        dim.setCpeKey(CpeUtil.buildCpeKey(parsed));
        return dim;
    }

    private String token(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
