package com.prototype.vulnwatch.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;
import com.prototype.vulnwatch.service.FixDemoDataSeeder;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/fix-intelligence")
public class FixIntelligenceController {

    @Autowired
    private FixDemoDataSeeder fixDemoDataSeeder;

    @GetMapping("/fixes")
    public Map<String, Object> listFixes(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String fixType,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String ecosystem) {

        List<Map<String, Object>> allFixes = fixDemoDataSeeder.generateDemoFixes();

        // Apply filters
        List<Map<String, Object>> filtered = allFixes.stream()
                .filter(f -> search == null ||
                        f.get("title").toString().toLowerCase().contains(search.toLowerCase()) ||
                        f.get("externalId").toString().toLowerCase().contains(search.toLowerCase()))
                .filter(f -> fixType == null || f.get("fixType").equals(fixType))
                .filter(f -> severity == null || f.get("severity").equals(severity))
                .filter(f -> ecosystem == null || f.get("ecosystem").equals(ecosystem))
                .collect(Collectors.toList());

        // Pagination
        int total = filtered.size();
        int start = page * size;
        int end = Math.min(start + size, total);
        List<Map<String, Object>> paginated = filtered.subList(start, end);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("content", paginated);
        response.put("totalElements", total);
        response.put("totalPages", (total + size - 1) / size);
        response.put("currentPage", page);
        response.put("pageSize", size);
        response.put("hasNext", end < total);
        response.put("hasPrevious", page > 0);

        return response;
    }

    @GetMapping("/fixes/{fixId}")
    public Map<String, Object> getFixDetail(@PathVariable String fixId) {
        return fixDemoDataSeeder.generateDemoFixes().stream()
                .filter(f -> f.get("externalId").equals(fixId))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Fix not found: " + fixId));
    }

    @GetMapping("/statistics")
    public Map<String, Object> getStatistics() {
        List<Map<String, Object>> allFixes = fixDemoDataSeeder.generateDemoFixes();

        Map<String, Object> stats = new LinkedHashMap<>();

        // Count by type
        Map<String, Long> byType = allFixes.stream()
                .collect(Collectors.groupingBy(f -> f.get("fixType").toString(), Collectors.counting()));
        stats.put("byType", byType);

        // Count by severity
        Map<String, Long> bySeverity = allFixes.stream()
                .collect(Collectors.groupingBy(f -> f.get("severity").toString(), Collectors.counting()));
        stats.put("bySeverity", bySeverity);

        // Count by ecosystem
        Map<String, Long> byEcosystem = allFixes.stream()
                .collect(Collectors.groupingBy(f -> f.get("ecosystem").toString(), Collectors.counting()));
        stats.put("byEcosystem", byEcosystem);

        // Count by source
        Map<String, Long> bySource = allFixes.stream()
                .collect(Collectors.groupingBy(f -> f.get("sourceSystem").toString(), Collectors.counting()));
        stats.put("bySource", bySource);

        // Overall metrics
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("totalFixes", allFixes.size());
        metrics.put("avgDeploymentRate", allFixes.stream()
                .mapToDouble(f -> ((Number) f.get("deploymentRate")).doubleValue())
                .average()
                .orElse(0.0));
        metrics.put("criticalCount", bySeverity.getOrDefault("Critical", 0L));
        metrics.put("highCount", bySeverity.getOrDefault("High", 0L));
        stats.put("metrics", metrics);

        return stats;
    }

    @GetMapping("/fixes-by-type/{type}")
    public Map<String, Object> getFixesByType(
            @PathVariable String type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size) {

        List<Map<String, Object>> allFixes = fixDemoDataSeeder.generateDemoFixes().stream()
                .filter(f -> f.get("fixType").equals(type))
                .collect(Collectors.toList());

        int total = allFixes.size();
        int start = page * size;
        int end = Math.min(start + size, total);
        List<Map<String, Object>> paginated = allFixes.subList(start, end);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("content", paginated);
        response.put("fixType", type);
        response.put("totalElements", total);
        response.put("totalPages", (total + size - 1) / size);

        return response;
    }
}
