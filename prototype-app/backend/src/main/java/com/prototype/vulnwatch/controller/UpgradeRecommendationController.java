package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.UpgradeRecommendationRequest;
import com.prototype.vulnwatch.dto.UpgradeRecommendationResponse;
import com.prototype.vulnwatch.service.UpgradeRecommendationService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/upgrade-recommendation")
public class UpgradeRecommendationController {

    private final UpgradeRecommendationService upgradeRecommendationService;

    public UpgradeRecommendationController(UpgradeRecommendationService upgradeRecommendationService) {
        this.upgradeRecommendationService = upgradeRecommendationService;
    }

    @PostMapping
    public UpgradeRecommendationResponse getRecommendation(
        @RequestBody UpgradeRecommendationRequest request
    ) {
        return upgradeRecommendationService.getRecommendation(request);
    }
}
