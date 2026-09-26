package com.prototype.vulnwatch.dto.patch;

import com.prototype.vulnwatch.domain.CveFixMap;
import com.prototype.vulnwatch.domain.Fix;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FixNormalizationResult {
    private Fix fix;
    private List<CveFixMap> cveMappings;
    private double confidenceScore;
    private String normalizationNotes;
}
