package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.RiskPolicyRequest;
import com.prototype.vulnwatch.dto.RiskPolicyResponse;
import com.prototype.vulnwatch.service.RiskPolicyService;
import com.prototype.vulnwatch.service.TenantService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/risk-policy")
public class RiskPolicyController {

    private final TenantService tenantService;
    private final RiskPolicyService riskPolicyService;

    public RiskPolicyController(TenantService tenantService, RiskPolicyService riskPolicyService) {
        this.tenantService = tenantService;
        this.riskPolicyService = riskPolicyService;
    }

    @GetMapping
    public RiskPolicyResponse get() {
        Tenant tenant = tenantService.getDefaultTenant();
        return riskPolicyService.get(tenant);
    }

    @PostMapping
    public RiskPolicyResponse update(@RequestBody RiskPolicyRequest request) {
        Tenant tenant = tenantService.getDefaultTenant();
        return riskPolicyService.update(tenant, request);
    }
}
