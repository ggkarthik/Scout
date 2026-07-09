package com.prototype.vulnwatch.security;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class TestActuatorController {

    @GetMapping("/actuator/health/readiness")
    Map<String, String> readiness() {
        return Map.of("status", "UP");
    }

    @GetMapping("/actuator/prometheus")
    String prometheus() {
        return "scoutgrid_test_metric 1";
    }
}
