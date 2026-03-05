package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.repo.CpeDimRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
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
        String normalized = CpeUtil.normalizeCpe23(rawCpe);
        if (normalized == null) {
            return null;
        }

        Optional<CpeDim> existing = cpeDimRepository.findByNormalizedCpe(normalized);
        if (existing.isPresent()) {
            CpeDim dim = existing.get();
            dim.setRawCpe(rawCpe.trim());
            dim.touch();
            return cpeDimRepository.save(dim);
        }

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

        try {
            return cpeDimRepository.save(dim);
        } catch (DataIntegrityViolationException race) {
            return cpeDimRepository.findByNormalizedCpe(normalized)
                    .orElseThrow(() -> race);
        }
    }

    @Transactional
    public List<CpeDim> resolveOrCreateAll(Collection<String> rawCpes) {
        if (rawCpes == null || rawCpes.isEmpty()) {
            return List.of();
        }
        List<CpeDim> resolved = new ArrayList<>();
        for (String rawCpe : rawCpes) {
            CpeDim dim = resolveOrCreate(rawCpe);
            if (dim != null) {
                resolved.add(dim);
            }
        }
        return resolved.stream().filter(Objects::nonNull).distinct().toList();
    }

    private String token(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
