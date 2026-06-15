package com.prototype.vulnwatch.util;

public final class LogUtil {

    private LogUtil() {}

    /** Strip control characters that could be used for log injection. */
    public static String safe(String value) {
        if (value == null) return "null";
        return value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
    }
}
