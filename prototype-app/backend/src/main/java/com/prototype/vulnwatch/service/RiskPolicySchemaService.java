package com.prototype.vulnwatch.service;

import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class RiskPolicySchemaService {

    private static final Logger LOG = LoggerFactory.getLogger(RiskPolicySchemaService.class);

    private final JdbcTemplate jdbcTemplate;
    private final AtomicBoolean ensured = new AtomicBoolean(false);

    public RiskPolicySchemaService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void ensureColumns() {
        if (ensured.get()) {
            return;
        }
        synchronized (this) {
            if (ensured.get()) {
                return;
            }

            try {
                addColumn("vex_not_affected_freshness_days", "INT");
                addColumn("vex_fixed_freshness_days", "INT");
                addColumn("vex_known_affected_boost", "DOUBLE");
                addColumn("vex_under_investigation_penalty", "DOUBLE");
                addColumn("vex_not_affected_reduction", "DOUBLE");
                addColumn("vex_stale_penalty", "DOUBLE");

                jdbcTemplate.execute("""
                        UPDATE risk_policies
                        SET
                          vex_not_affected_freshness_days = COALESCE(vex_not_affected_freshness_days, 30),
                          vex_fixed_freshness_days = COALESCE(vex_fixed_freshness_days, 30),
                          vex_known_affected_boost = COALESCE(vex_known_affected_boost, 0.4),
                          vex_under_investigation_penalty = COALESCE(vex_under_investigation_penalty, 0.2),
                          vex_not_affected_reduction = COALESCE(vex_not_affected_reduction, 0.8),
                          vex_stale_penalty = COALESCE(vex_stale_penalty, 0.5)
                        """);
                ensured.set(true);
            } catch (Exception e) {
                // Keep service resilient for first-run bootstrap paths.
                LOG.warn("Risk policy schema compatibility check skipped: {}", e.getMessage());
            }
        }
    }

    private void addColumn(String column, String type) {
        jdbcTemplate.execute("ALTER TABLE risk_policies ADD COLUMN IF NOT EXISTS " + column + " " + type);
    }
}
