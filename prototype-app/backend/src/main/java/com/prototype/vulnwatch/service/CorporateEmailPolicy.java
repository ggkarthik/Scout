package com.prototype.vulnwatch.service;

import java.net.IDN;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;

public final class CorporateEmailPolicy {

    private static final Pattern DOMAIN_LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
    private static final Set<String> FREE_EMAIL_DOMAINS = Set.of(
            "126.com", "163.com", "aol.com", "fastmail.com", "gmx.com", "gmx.de", "googlemail.com",
            "gmail.com", "hey.com", "hotmail.co.uk", "hotmail.com", "hushmail.com", "icloud.com",
            "inbox.com", "laposte.net", "libero.it", "live.co.uk", "live.com", "mac.com", "mail.com",
            "me.com", "msn.com", "orange.fr", "outlook.com", "proton.me", "protonmail.com", "qq.com",
            "rambler.ru", "rediffmail.com", "tuta.com", "tutanota.com", "web.de", "yahoo.co.in",
            "yahoo.co.uk", "yahoo.com", "yahoo.in", "yandex.com", "yandex.ru", "zoho.com"
    );

    private CorporateEmailPolicy() {
    }

    public static boolean isCorporateEmail(String email) {
        if (email == null) {
            return false;
        }
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        int separator = normalized.lastIndexOf('@');
        if (separator <= 0 || separator == normalized.length() - 1 || normalized.indexOf('@') != separator) {
            return false;
        }
        String domain;
        try {
            domain = IDN.toASCII(normalized.substring(separator + 1));
        } catch (IllegalArgumentException invalidDomain) {
            return false;
        }
        if (!isValidDomain(domain) || FREE_EMAIL_DOMAINS.contains(domain)) {
            return false;
        }
        return !domain.startsWith("yahoo.") && !domain.startsWith("hotmail.") && !domain.startsWith("live.");
    }

    public static void requireCorporateEmail(String email) {
        if (!isCorporateEmail(email)) {
            throw new DemoAccessException(
                    "CORPORATE_EMAIL_REQUIRED",
                    "Enter a valid corporate email address. Free email providers are not accepted.",
                    HttpStatus.BAD_REQUEST);
        }
    }

    private static boolean isValidDomain(String domain) {
        if (domain.length() > 253 || domain.startsWith(".") || domain.endsWith(".") || !domain.contains(".")) {
            return false;
        }
        String[] labels = domain.split("\\.");
        if (labels.length < 2) {
            return false;
        }
        for (String label : labels) {
            if (!DOMAIN_LABEL.matcher(label).matches()) {
                return false;
            }
        }
        String topLevelDomain = labels[labels.length - 1];
        return topLevelDomain.startsWith("xn--") || topLevelDomain.matches("[a-z]{2,63}");
    }
}
