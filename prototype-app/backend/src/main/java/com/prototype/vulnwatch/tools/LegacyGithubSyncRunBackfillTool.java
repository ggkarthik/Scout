package com.prototype.vulnwatch.tools;

import com.prototype.vulnwatch.VulnWatchApplication;
import com.prototype.vulnwatch.service.LegacyGithubSyncRunBackfillService;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

public final class LegacyGithubSyncRunBackfillTool {

    private LegacyGithubSyncRunBackfillTool() {
    }

    public static void main(String[] args) {
        try (ConfigurableApplicationContext context = new SpringApplicationBuilder(VulnWatchApplication.class)
                .web(WebApplicationType.NONE)
                .run(args)) {
            int created = context.getBean(LegacyGithubSyncRunBackfillService.class).backfillMissingRuns();
            System.out.println("Legacy GitHub sync runs backfilled: " + created);
        }
    }
}
