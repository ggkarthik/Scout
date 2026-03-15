package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CiAlias;
import com.prototype.vulnwatch.domain.DiscoveryModel;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import java.util.Locale;

final class HostInventoryReviewEvaluator {

    static final double LOW_CONFIDENCE_ALIAS_THRESHOLD = 0.9d;

    private HostInventoryReviewEvaluator() {
    }

    static boolean needsVersionReview(SoftwareInstance instance) {
        return instance != null
                && instance.isActiveInstall()
                && !hasText(instance.getVersion())
                && !hasText(instance.getNormalizedVersion());
    }

    static boolean needsIdentityReview(SoftwareInstance instance) {
        return instance != null
                && instance.isActiveInstall()
                && instance.getSoftwareIdentity() == null;
    }

    static boolean needsDiscoveryModelReview(SoftwareInstance instance) {
        if (instance == null || !instance.isActiveInstall()) {
            return false;
        }
        DiscoveryModel model = instance.getDiscoveryModel();
        return model != null
                && (model.isLowConfidence()
                || !model.isApproved()
                || (hasText(model.getNormalizationStatus())
                && !"approved".equals(normalize(model.getNormalizationStatus()))));
    }

    static boolean isLowConfidenceAlias(CiAlias alias) {
        return alias != null
                && alias.getConfidence() != null
                && alias.getConfidence() < LOW_CONFIDENCE_ALIAS_THRESHOLD;
    }

    static boolean sourceMatches(String rowSourceSystem, String componentSourceSystem) {
        if (!hasText(componentSourceSystem)) {
            return true;
        }
        return normalize(rowSourceSystem).equals(normalize(componentSourceSystem));
    }

    static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replace('_', '-').replace(' ', '-');
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
