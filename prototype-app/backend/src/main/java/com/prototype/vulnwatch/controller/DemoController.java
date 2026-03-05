package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.DemoSeedService;
import com.prototype.vulnwatch.dto.IngestionResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/demo")
public class DemoController {

    private final DemoSeedService demoSeedService;

    public DemoController(DemoSeedService demoSeedService) {
        this.demoSeedService = demoSeedService;
    }

    @PostMapping("/seed")
    public IngestionResult seed() {
        return demoSeedService.seedAdvisories();
    }
}
