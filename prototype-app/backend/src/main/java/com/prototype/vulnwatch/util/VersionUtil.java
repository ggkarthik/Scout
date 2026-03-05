package com.prototype.vulnwatch.util;

import com.prototype.vulnwatch.domain.VersionScheme;
import org.apache.maven.artifact.versioning.ComparableVersion;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class VersionUtil {
    private VersionUtil() {
    }

    public static boolean matches(
            String componentVersion,
            String exact,
            String start,
            Boolean startInclusive,
            String end,
            Boolean endInclusive
    ) {
        return matches(
                componentVersion,
                exact,
                start,
                startInclusive,
                end,
                endInclusive,
                null,
                null,
                VersionScheme.UNKNOWN
        );
    }

    public static boolean matches(
            String componentVersion,
            String exact,
            String start,
            Boolean startInclusive,
            String end,
            Boolean endInclusive,
            String introduced,
            String fixed,
            VersionScheme scheme
    ) {
        if (componentVersion == null || componentVersion.isBlank()) {
            return false;
        }

        VersionScheme safeScheme = scheme == null ? VersionScheme.UNKNOWN : scheme;

        if (exact != null && !exact.isBlank()) {
            return compare(componentVersion, exact, safeScheme) == 0;
        }

        if (introduced != null && !introduced.isBlank()) {
            int compareIntroduced = compare(componentVersion, introduced, safeScheme);
            if (compareIntroduced < 0) {
                return false;
            }
        }

        if (fixed != null && !fixed.isBlank()) {
            int compareFixed = compare(componentVersion, fixed, safeScheme);
            if (compareFixed >= 0) {
                return false;
            }
        }

        if (start != null && !start.isBlank()) {
            int compareStart = compare(componentVersion, start, safeScheme);
            boolean inclusive = startInclusive == null || startInclusive;
            if (inclusive && compareStart < 0) {
                return false;
            }
            if (!inclusive && compareStart <= 0) {
                return false;
            }
        }

        if (end != null && !end.isBlank()) {
            int compareEnd = compare(componentVersion, end, safeScheme);
            boolean inclusive = endInclusive == null || endInclusive;
            if (inclusive && compareEnd > 0) {
                return false;
            }
            if (!inclusive && compareEnd >= 0) {
                return false;
            }
        }

        return true;
    }

    public static int compare(String a, String b) {
        return compare(a, b, VersionScheme.UNKNOWN);
    }

    public static int compare(String a, String b, VersionScheme scheme) {
        VersionScheme safeScheme = scheme == null ? VersionScheme.UNKNOWN : scheme;
        return switch (safeScheme) {
            case LEXICAL -> normalize(a).compareTo(normalize(b));
            case PEP440 -> comparePep440(a, b);
            case DPKG -> compareDpkg(a, b);
            case RPM -> compareRpm(a, b);
            case SEMVER, MAVEN -> compareComparable(a, b);
            case UNKNOWN -> compareComparable(a, b);
        };
    }

    private static String normalize(String v) {
        if (v == null) {
            return "";
        }
        String normalized = v.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("v") && normalized.length() > 1) {
            return normalized.substring(1);
        }
        return normalized;
    }

    private static int compareComparable(String a, String b) {
        ComparableVersion left = new ComparableVersion(normalize(a));
        ComparableVersion right = new ComparableVersion(normalize(b));
        return left.compareTo(right);
    }

    // PEP 440 comparator with deterministic parsing for common forms used by Python ecosystems.
    private static int comparePep440(String a, String b) {
        Pep440Version left = parsePep440(a);
        Pep440Version right = parsePep440(b);

        int epochCompare = Integer.compare(left.epoch, right.epoch);
        if (epochCompare != 0) {
            return epochCompare;
        }

        int releaseCompare = compareRelease(left.release, right.release);
        if (releaseCompare != 0) {
            return releaseCompare;
        }

        if (left.preRank != right.preRank) {
            return Integer.compare(left.preRank, right.preRank);
        }
        if (left.preRank < 3) {
            int preTypeCompare = Integer.compare(left.preTypeOrder, right.preTypeOrder);
            if (preTypeCompare != 0) {
                return preTypeCompare;
            }
            int preNumberCompare = Integer.compare(left.preNumber, right.preNumber);
            if (preNumberCompare != 0) {
                return preNumberCompare;
            }
        }

        if (left.postNumber != right.postNumber) {
            return Integer.compare(left.postNumber, right.postNumber);
        }

        return 0;
    }

    private static final Pattern PEP440_PATTERN = Pattern.compile(
            "^(?:(\\d+)!)?(\\d+(?:\\.\\d+)*)(?:(a|b|rc|alpha|beta|pre|preview|c)(\\d*))?(?:\\.?((?:post|rev|r))(\\d*))?(?:\\.(dev)(\\d*))?$",
            Pattern.CASE_INSENSITIVE
    );

    private static Pep440Version parsePep440(String value) {
        String normalized = normalize(value).replace("-", ".").replace("_", ".");
        int localSep = normalized.indexOf('+');
        if (localSep >= 0) {
            normalized = normalized.substring(0, localSep);
        }

        Matcher matcher = PEP440_PATTERN.matcher(normalized);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid PEP440 version: " + value);
        }

        int epoch = parseIntOrDefault(matcher.group(1), 0, "Invalid PEP440 epoch: " + value);
        List<Integer> release = parseReleaseTuple(matcher.group(2), value);

        String rawPreType = normalizePreType(matcher.group(3));
        int preTypeOrder = switch (rawPreType) {
            case "a" -> 0;
            case "b" -> 1;
            case "rc" -> 2;
            default -> 3;
        };
        int preNumber = parseIntOrDefault(matcher.group(4), 0, "Invalid PEP440 pre-release number: " + value);

        boolean hasDev = matcher.group(7) != null;
        int devNumber = parseIntOrDefault(matcher.group(8), 0, "Invalid PEP440 dev number: " + value);
        boolean hasPre = preTypeOrder < 3;
        boolean hasPost = matcher.group(5) != null;
        int postNumber = hasPost ? parseIntOrDefault(matcher.group(6), 0, "Invalid PEP440 post number: " + value) : -1;

        // Ordering: dev < pre < final < post
        int preRank;
        if (hasDev && !hasPre && !hasPost) {
            preRank = 0;
        } else if (hasPre) {
            preRank = hasDev ? 0 : 1;
        } else if (!hasPost) {
            preRank = 2;
        } else {
            preRank = 3;
        }

        if (hasDev && !hasPre && hasPost) {
            // 1.0.post1.dev1 is uncommon; keep deterministic by treating it before post.
            preRank = 2;
            postNumber = Math.max(0, postNumber) - 1;
        }

        return new Pep440Version(epoch, release, preRank, preTypeOrder, preNumber, postNumber, devNumber);
    }

    private static int compareRelease(List<Integer> left, List<Integer> right) {
        int length = Math.max(left.size(), right.size());
        for (int i = 0; i < length; i++) {
            int l = i < left.size() ? left.get(i) : 0;
            int r = i < right.size() ? right.get(i) : 0;
            int cmp = Integer.compare(l, r);
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    private static String normalizePreType(String value) {
        if (value == null) {
            return "";
        }
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "alpha" -> "a";
            case "beta" -> "b";
            case "pre", "preview", "c" -> "rc";
            default -> value.toLowerCase(Locale.ROOT);
        };
    }

    private static List<Integer> parseReleaseTuple(String value, String source) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Invalid release tuple in PEP440 version: " + source);
        }
        String[] segments = value.split("\\.");
        List<Integer> numbers = new ArrayList<>(segments.length);
        for (String segment : segments) {
            if (segment.isBlank()) {
                throw new IllegalArgumentException("Invalid release tuple in PEP440 version: " + source);
            }
            numbers.add(parseIntOrDefault(segment, 0, "Invalid release segment in PEP440 version: " + source));
        }
        return numbers;
    }

    private record Pep440Version(
            int epoch,
            List<Integer> release,
            int preRank,
            int preTypeOrder,
            int preNumber,
            int postNumber,
            int devNumber
    ) {
    }

    private static int compareDpkg(String a, String b) {
        DebianVersion left = parseDebianVersion(a);
        DebianVersion right = parseDebianVersion(b);

        int epochCompare = Integer.compare(left.epoch(), right.epoch());
        if (epochCompare != 0) {
            return epochCompare;
        }
        int upstreamCompare = compareDpkgPart(left.upstream(), right.upstream());
        if (upstreamCompare != 0) {
            return upstreamCompare;
        }
        return compareDpkgPart(left.revision(), right.revision());
    }

    private static DebianVersion parseDebianVersion(String value) {
        String normalized = value == null ? "" : value.trim();
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Invalid DPKG version: blank");
        }

        int epoch = 0;
        String rest = normalized;
        int epochSep = normalized.indexOf(':');
        if (epochSep >= 0) {
            epoch = parseIntOrDefault(normalized.substring(0, epochSep), 0, "Invalid DPKG epoch: " + value);
            rest = normalized.substring(epochSep + 1);
        }

        String upstream = rest;
        String revision = "";
        int revisionSep = rest.lastIndexOf('-');
        if (revisionSep >= 0) {
            upstream = rest.substring(0, revisionSep);
            revision = rest.substring(revisionSep + 1);
        }
        if (upstream.isBlank()) {
            throw new IllegalArgumentException("Invalid DPKG upstream version: " + value);
        }
        return new DebianVersion(epoch, upstream, revision);
    }

    private static int compareDpkgPart(String leftValue, String rightValue) {
        String left = leftValue == null ? "" : leftValue;
        String right = rightValue == null ? "" : rightValue;
        int i = 0;
        int j = 0;

        while (i < left.length() || j < right.length()) {
            while ((i < left.length() && !Character.isDigit(left.charAt(i)))
                    || (j < right.length() && !Character.isDigit(right.charAt(j)))) {
                int leftOrder = dpkgCharOrder(i < left.length() ? left.charAt(i) : 0);
                int rightOrder = dpkgCharOrder(j < right.length() ? right.charAt(j) : 0);
                if (leftOrder != rightOrder) {
                    return Integer.compare(leftOrder, rightOrder);
                }
                if (i < left.length()) {
                    i++;
                }
                if (j < right.length()) {
                    j++;
                }
            }

            int iStart = i;
            while (i < left.length() && left.charAt(i) == '0') {
                i++;
            }
            int jStart = j;
            while (j < right.length() && right.charAt(j) == '0') {
                j++;
            }

            int iDigitsStart = i;
            while (i < left.length() && Character.isDigit(left.charAt(i))) {
                i++;
            }
            int jDigitsStart = j;
            while (j < right.length() && Character.isDigit(right.charAt(j))) {
                j++;
            }

            int leftDigits = i - iDigitsStart;
            int rightDigits = j - jDigitsStart;
            if (leftDigits != rightDigits) {
                return Integer.compare(leftDigits, rightDigits);
            }
            for (int idx = 0; idx < leftDigits; idx++) {
                char lc = left.charAt(iDigitsStart + idx);
                char rc = right.charAt(jDigitsStart + idx);
                if (lc != rc) {
                    return Character.compare(lc, rc);
                }
            }

            // If one side had only zeroes and the other had no digit segment, continue lexical loop.
            if (leftDigits == 0 && rightDigits == 0) {
                i = iStart;
                j = jStart;
                if (i < left.length()) {
                    i++;
                }
                if (j < right.length()) {
                    j++;
                }
            }
        }
        return 0;
    }

    private static int dpkgCharOrder(char c) {
        if (c == 0) {
            return 0;
        }
        if (c == '~') {
            return -1;
        }
        if (Character.isLetter(c)) {
            return c;
        }
        return c + 256;
    }

    private record DebianVersion(int epoch, String upstream, String revision) {
    }

    private static int compareRpm(String a, String b) {
        String left = normalizeRpm(a);
        String right = normalizeRpm(b);
        int li = 0;
        int ri = 0;

        while (true) {
            li = skipRpmSeparators(left, li);
            ri = skipRpmSeparators(right, ri);

            char leftChar = li < left.length() ? left.charAt(li) : 0;
            char rightChar = ri < right.length() ? right.charAt(ri) : 0;
            if (leftChar == '~' || rightChar == '~') {
                if (leftChar != '~') {
                    return 1;
                }
                if (rightChar != '~') {
                    return -1;
                }
                li++;
                ri++;
                continue;
            }

            boolean leftEnd = li >= left.length();
            boolean rightEnd = ri >= right.length();
            if (leftEnd || rightEnd) {
                if (leftEnd && rightEnd) {
                    return 0;
                }
                return leftEnd ? -1 : 1;
            }

            boolean leftNumeric = Character.isDigit(left.charAt(li));
            boolean rightNumeric = Character.isDigit(right.charAt(ri));
            if (leftNumeric != rightNumeric) {
                return leftNumeric ? 1 : -1;
            }

            String leftSeg = readRpmSegment(left, li, leftNumeric);
            String rightSeg = readRpmSegment(right, ri, rightNumeric);

            li += leftSeg.length();
            ri += rightSeg.length();

            int segCompare = leftNumeric
                    ? compareNumericSegment(leftSeg, rightSeg)
                    : leftSeg.compareTo(rightSeg);
            if (segCompare != 0) {
                return segCompare;
            }
        }
    }

    private static String normalizeRpm(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Invalid RPM version: blank");
        }
        return normalized;
    }

    private static int skipRpmSeparators(String value, int index) {
        int i = index;
        while (i < value.length()) {
            char c = value.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '~') {
                break;
            }
            i++;
        }
        return i;
    }

    private static String readRpmSegment(String value, int index, boolean numeric) {
        int i = index;
        while (i < value.length()) {
            char c = value.charAt(i);
            if (numeric && !Character.isDigit(c)) {
                break;
            }
            if (!numeric && !Character.isLetter(c)) {
                break;
            }
            i++;
        }
        return value.substring(index, i);
    }

    private static int compareNumericSegment(String left, String right) {
        String l = stripLeadingZeros(left);
        String r = stripLeadingZeros(right);
        if (l.length() != r.length()) {
            return Integer.compare(l.length(), r.length());
        }
        return l.compareTo(r);
    }

    private static String stripLeadingZeros(String value) {
        int i = 0;
        while (i < value.length() && value.charAt(i) == '0') {
            i++;
        }
        if (i == value.length()) {
            return "0";
        }
        return value.substring(i);
    }

    private static int parseIntOrDefault(String value, int fallback, String message) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(message, e);
        }
    }
}
