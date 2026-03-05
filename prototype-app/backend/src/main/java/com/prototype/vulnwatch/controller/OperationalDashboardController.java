package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.OperationalDashboardResponse;
import com.prototype.vulnwatch.service.OperationalDashboardService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/operations")
public class OperationalDashboardController {

    private final OperationalDashboardService operationalDashboardService;

    public OperationalDashboardController(OperationalDashboardService operationalDashboardService) {
        this.operationalDashboardService = operationalDashboardService;
    }

    @GetMapping("/dashboard")
    public OperationalDashboardResponse get() {
        return operationalDashboardService.get();
    }
}
