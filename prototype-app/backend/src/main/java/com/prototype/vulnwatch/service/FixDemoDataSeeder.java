package com.prototype.vulnwatch.service;

import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class FixDemoDataSeeder {

    private static final Random RANDOM = new Random(42);
    private static final ObjectMapper mapper = new ObjectMapper();

    public List<Map<String, Object>> generateDemoFixes() {
        List<Map<String, Object>> fixes = new ArrayList<>();

        // Windows Patches (40 fixes)
        fixes.addAll(generateWindowsPatches());

        // Linux Patches (30 fixes)
        fixes.addAll(generateLinuxPatches());

        // macOS Patches (15 fixes)
        fixes.addAll(generateMacOSPatches());

        // Workarounds (10 fixes)
        fixes.addAll(generateWorkarounds());

        // Compensating Controls (5 fixes)
        fixes.addAll(generateCompensatingControls());

        return fixes;
    }

    private List<Map<String, Object>> generateWindowsPatches() {
        List<Map<String, Object>> patches = new ArrayList<>();
        String[] titles = {
            "Critical Security Update",
            "Privilege Escalation Fix",
            "Remote Code Execution Patch",
            "Information Disclosure Prevention",
            "Denial of Service Mitigation",
            "Buffer Overflow Protection",
            "SQL Injection Prevention",
            "Cross-Site Scripting Fix",
            "Authentication Bypass Patch",
            "Kernel Security Update"
        };

        for (int i = 1; i <= 40; i++) {
            String title = titles[(i - 1) % titles.length] + " KB5" + (30000 + i);
            patches.add(createFix(
                "KB5" + (30000 + i),
                title,
                "SCCM",
                "Windows",
                "Windows Server 2022",
                "21H2",
                "PATCH",
                getRandomSeverity(),
                randomRange(500, 2000),
                randomRange(300, 1800),
                true,
                randomRange(10, 30)
            ));
        }
        return patches;
    }

    private List<Map<String, Object>> generateLinuxPatches() {
        List<Map<String, Object>> patches = new ArrayList<>();
        String[] distros = { "Ubuntu", "CentOS", "RHEL", "Debian", "Amazon Linux" };
        String[] components = { "kernel", "openssl", "glibc", "systemd", "openssh", "sudo" };
        String[] titles = {
            "Security Update for",
            "Critical Patch for",
            "Urgent Fix for",
            "Maintenance Update for"
        };

        for (int i = 1; i <= 30; i++) {
            String distro = distros[i % distros.length];
            String component = components[(i / 6) % components.length];
            String title = titles[(i / 8) % titles.length] + " " + component + " (" + distro + ")";
            patches.add(createFix(
                "RHSA-2026:" + String.format("%03d", i),
                title,
                "BigFix",
                "Linux",
                component,
                "6." + i % 5,
                "PATCH",
                getRandomSeverity(),
                randomRange(200, 1500),
                randomRange(100, 1200),
                i % 3 == 0,
                randomRange(0, 20)
            ));
        }
        return patches;
    }

    private List<Map<String, Object>> generateMacOSPatches() {
        List<Map<String, Object>> patches = new ArrayList<>();
        for (int i = 1; i <= 15; i++) {
            patches.add(createFix(
                "MACOS-SEC-" + String.format("%04d", 2000 + i),
                "Security Update for macOS 14." + (i % 5),
                "Tanium",
                "macOS",
                "macOS",
                "14." + (i % 5),
                "PATCH",
                i % 5 == 0 ? "Critical" : i % 3 == 0 ? "High" : "Medium",
                randomRange(50, 800),
                randomRange(30, 700),
                false,
                0
            ));
        }
        return patches;
    }

    private List<Map<String, Object>> generateWorkarounds() {
        List<Map<String, Object>> workarounds = new ArrayList<>();
        String[] titles = {
            "Workaround: Disable TLS 1.0",
            "Workaround: Enable Address Space Layout Randomization",
            "Workaround: Restrict Network Access",
            "Workaround: Disable Legacy Protocols",
            "Workaround: Configure Security Groups",
            "Workaround: Enable Enhanced Security",
            "Workaround: Implement Web Application Firewall",
            "Workaround: Apply Security Policies",
            "Workaround: Segment Networks",
            "Workaround: Monitor Suspicious Activities"
        };

        for (int i = 0; i < 10; i++) {
            workarounds.add(createFix(
                "WRK-" + String.format("%04d", 1000 + i),
                titles[i],
                "MANUAL",
                "Cross-platform",
                "Multiple",
                "All",
                "WORKAROUND",
                i % 3 == 0 ? "High" : "Medium",
                randomRange(100, 500),
                randomRange(50, 300),
                false,
                0
            ));
        }
        return workarounds;
    }

    private List<Map<String, Object>> generateCompensatingControls() {
        List<Map<String, Object>> controls = new ArrayList<>();
        String[] titles = {
            "Compensating Control: Multi-Factor Authentication",
            "Compensating Control: Zero Trust Network Access",
            "Compensating Control: Endpoint Detection and Response",
            "Compensating Control: Behavior-Based Threat Detection",
            "Compensating Control: Intrusion Prevention System"
        };

        for (int i = 0; i < 5; i++) {
            controls.add(createFix(
                "CC-" + String.format("%04d", 5000 + i),
                titles[i],
                "MANUAL",
                "Cross-platform",
                "Infrastructure",
                "N/A",
                "COMPENSATING_CONTROL",
                "High",
                randomRange(200, 800),
                randomRange(100, 600),
                false,
                0
            ));
        }
        return controls;
    }

    private Map<String, Object> createFix(
            String externalId, String title, String sourceSystem, String ecosystem,
            String packageName, String fixedVersion, String fixType, String severity,
            int applicableAssets, int deployedAssets, boolean requiresReboot,
            int estimatedDowntime) {

        Map<String, Object> fix = new LinkedHashMap<>();
        fix.put("externalId", externalId);
        fix.put("title", title);
        fix.put("sourceSystem", sourceSystem);
        fix.put("ecosystem", ecosystem);
        fix.put("packageName", packageName);
        fix.put("fixedVersion", fixedVersion);
        fix.put("fixType", fixType);
        fix.put("severity", severity);
        fix.put("applicableAssets", applicableAssets);
        fix.put("deployedAssets", deployedAssets);
        fix.put("deploymentRate", (deployedAssets * 100.0) / applicableAssets);
        fix.put("requiresReboot", requiresReboot);
        fix.put("estimatedDowntimeMinutes", estimatedDowntime);
        fix.put("status", "ACTIVE");

        String description = generateDescription(fixType, ecosystem, title);
        fix.put("description", description);

        fix.put("installationInstructions", generateInstallationInstructions(fixType, sourceSystem));
        fix.put("knownLimitations", "Test in staging environment before production deployment.");
        fix.put("patchUrl", "https://example.com/patch/" + externalId);

        ObjectNode metadata = mapper.createObjectNode();
        metadata.put("releaseDate", Instant.now().minus(RANDOM.nextInt(90), ChronoUnit.DAYS).toString());
        metadata.put("classification", fixType);
        metadata.put("priority", severity);
        fix.put("sourceMetadata", metadata.toString());

        fix.put("createdAt", Instant.now().minus(RANDOM.nextInt(30), ChronoUnit.DAYS).toString());
        fix.put("syncedAt", Instant.now().toString());

        return fix;
    }

    private String generateDescription(String fixType, String ecosystem, String title) {
        if ("WORKAROUND".equals(fixType)) {
            return "This is a configuration-based workaround for " + ecosystem + ". " +
                   "Implement this workaround to mitigate the risk until a permanent patch is available.";
        } else if ("COMPENSATING_CONTROL".equals(fixType)) {
            return "Deploy this compensating control across your " + ecosystem + " infrastructure. " +
                   "This control provides defense-in-depth protection while patches are being deployed.";
        } else {
            return "This critical patch addresses multiple vulnerabilities in " + ecosystem + ". " +
                   "Deploy as soon as possible to prevent exploitation. " + title;
        }
    }

    private String generateInstallationInstructions(String fixType, String sourceSystem) {
        if ("PATCH".equals(fixType)) {
            if ("SCCM".equals(sourceSystem)) {
                return "1. Open SCCM Console\n2. Go to Software Updates > All Software Updates\n3. Search for the KB number\n4. Select the update and click Deploy\n5. Choose deployment collection\n6. Wait for client deployment\n7. Reboot systems in maintenance window";
            } else if ("BigFix".equals(sourceSystem)) {
                return "1. Access BigFix Console\n2. Navigate to Relevance > Fixlets\n3. Search for the patch ID\n4. Create deployment action\n5. Select target computers\n6. Schedule deployment\n7. Monitor deployment status";
            } else {
                return "1. Login to Tanium Console\n2. Navigate to Patch Management\n3. Search for the patch\n4. Create deployment package\n5. Schedule installation\n6. Monitor client status\n7. Verify deployment completion";
            }
        } else if ("WORKAROUND".equals(fixType)) {
            return "1. Review the workaround documentation\n2. Implement configuration changes\n3. Test in non-production environment\n4. Deploy to production systems\n5. Verify effectiveness\n6. Monitor for any issues";
        } else {
            return "1. Review control documentation\n2. Prepare infrastructure\n3. Deploy control components\n4. Validate control operation\n5. Monitor control effectiveness\n6. Update security policies";
        }
    }

    private String getRandomSeverity() {
        int rand = RANDOM.nextInt(100);
        if (rand < 20) return "Critical";
        if (rand < 40) return "High";
        if (rand < 70) return "Medium";
        return "Low";
    }

    private int randomRange(int min, int max) {
        return min + RANDOM.nextInt(max - min + 1);
    }
}
