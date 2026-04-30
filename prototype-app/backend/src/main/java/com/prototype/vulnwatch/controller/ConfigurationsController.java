package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.PrototypeDataResetResponse;
import com.prototype.vulnwatch.service.PrototypeDataResetService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/configurations")
public class ConfigurationsController {

    private final PrototypeDataResetService prototypeDataResetService;

    public ConfigurationsController(PrototypeDataResetService prototypeDataResetService) {
        this.prototypeDataResetService = prototypeDataResetService;
    }

    @PostMapping("/clean-all")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public PrototypeDataResetResponse cleanAllPrototypeData() {
        return prototypeDataResetService.cleanAll();
    }
}
