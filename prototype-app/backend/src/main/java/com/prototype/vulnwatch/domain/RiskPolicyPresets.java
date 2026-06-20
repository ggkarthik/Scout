package com.prototype.vulnwatch.domain;

/**
 * Built-in policy presets that should be visible on a fresh tenant without
 * requiring the user to create their first rule from scratch.
 */
public final class RiskPolicyPresets {

    public static final String DEFAULT_FINDINGS_SCORE_CONFIG_JSON = """
            [
              {
                "table": "VULNERABILITY",
                "column": "cvssScore",
                "values": [
                  { "operator": ">=", "value": "9", "weight": 0.2 },
                  { "operator": "<=", "value": "8", "weight": 0.1 }
                ]
              },
              {
                "table": "VULNERABILITY",
                "column": "exploitExists",
                "values": [
                  { "operator": "=", "value": "true", "weight": 0.2 }
                ]
              },
              {
                "table": "ASSET",
                "column": "businessCriticality",
                "values": [
                  { "operator": "=", "value": "high", "weight": 0.2 }
                ]
              },
              {
                "table": "ASSET",
                "column": "internetFacing",
                "values": [
                  { "operator": "=", "value": "true", "weight": 0.2 }
                ]
              },
              {
                "table": "VULNERABILITY",
                "column": "isInKev",
                "values": [
                  { "operator": "=", "value": "true", "weight": 0.2 }
                ]
              }
            ]
            """.trim();

    private RiskPolicyPresets() {
    }
}
