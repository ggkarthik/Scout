package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.CbomRiskSeverity;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Comparator;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class CbomRiskScorer {

    public BigDecimal scoreComponent(CbomComponent component, List<CbomRiskFinding> findings) {
        double base = findings.stream()
                .map(CbomRiskFinding::getSeverity)
                .mapToDouble(this::severityScore)
                .max()
                .orElse(0.5);
        double sensitivity = switch (normalize(component.getSensitivity())) {
            case "critical", "secret", "restricted", "high" -> 1.25;
            case "internal", "medium" -> 1.0;
            case "public", "low" -> 0.75;
            default -> 1.0;
        };
        double exposure = switch (normalize(component.getTransmission())) {
            case "internet", "external", "public" -> 1.2;
            case "network", "internal" -> 1.0;
            case "local", "none" -> 0.85;
            default -> 1.0;
        };
        double state = switch (normalize(component.getState())) {
            case "compromised" -> 1.5;
            case "active" -> 1.0;
            case "deactivated", "destroyed", "retired" -> 0.4;
            default -> 1.0;
        };
        return BigDecimal.valueOf(Math.min(10.0, base * sensitivity * exposure * state))
                .setScale(2, RoundingMode.HALF_UP);
    }

    public BigDecimal scorePosture(List<CbomComponent> components) {
        if (components == null || components.isEmpty()) {
            return BigDecimal.ZERO.setScale(2, RoundingMode.HALF_UP);
        }
        List<Double> scores = components.stream()
                .map(CbomComponent::getRiskScore)
                .map(score -> score == null ? 0.0 : score.doubleValue())
                .sorted(Comparator.reverseOrder())
                .toList();
        double max = scores.get(0);
        double topMean = scores.stream().limit(3).mapToDouble(Double::doubleValue).average().orElse(0.0);
        return BigDecimal.valueOf((max * 0.6) + (topMean * 0.4)).setScale(2, RoundingMode.HALF_UP);
    }

    private double severityScore(CbomRiskSeverity severity) {
        if (severity == null) return 0.5;
        return switch (severity) {
            case CRITICAL -> 9.5;
            case HIGH -> 7.5;
            case MEDIUM -> 5.0;
            case LOW -> 2.5;
            case INFO -> 0.5;
        };
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase();
    }
}
