package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.util.VersionUtil;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/** Pure, bounded document traversal. No finding or inventory lifecycle writes. */
public final class AiBomCorrelationResolver {
    private AiBomCorrelationResolver() { }

    public record Limits(int depth, int nodes, int edges, int paths) {
        public Limits {
            if (depth < 1 || nodes < 1 || edges < 1 || paths < 1) {
                throw new IllegalArgumentException("Correlation limits must be positive");
            }
        }
    }
    public record Node(UUID id, String ref, String name, String namespace, String ecosystem,
                       String version, String purl, boolean software) { }
    public record Edge(UUID id, UUID source, UUID target, String sourceRef, String targetRef, String type) {
        public String key() { return sourceRef.length() + ":" + sourceRef + type.length() + ":" + type + targetRef.length() + ":" + targetRef; }
    }
    public record Package(UUID id, String name, String namespace, String ecosystem,
                          String version, String purl, boolean active) { }
    public record Path(List<UUID> components, List<UUID> relationships, List<String> refs,
                       List<String> edgeKeys, UUID terminal, String method, String fingerprint) { }
    public record Gap(UUID component, String ref, String reason) { }
    public record Result(List<Path> paths, Set<Gap> gaps, Set<String> edgeKeys, boolean complete) {
        /** Definitely removed edges retire independently of gaps on other branches. */
        public boolean preserves(List<String> oldRefs, List<String> oldEdges) {
            if (!edgeKeys.containsAll(oldEdges)) return false;
            return gaps.stream().anyMatch(g -> g.ref() == null || oldRefs.contains(g.ref()));
        }
    }
    private record Identity(String ecosystem, String namespace, String name, String version, String suffix) { }
    private record Candidate(Package component, Identity identity) { }
    private record InventoryIndex(Map<List<String>, List<Candidate>> identities, Set<List<String>> conflicting) { }

    private static List<String> coordinates(Identity i) { return List.of(i.ecosystem(), i.namespace(), i.name()); }
    private static InventoryIndex index(List<Package> inventory) {
        Map<List<String>, List<Candidate>> identities = new HashMap<>();
        Set<List<String>> conflicting = new HashSet<>();
        for (Package p : inventory) {
            try {
                Identity identity = identity(p.purl(), p.ecosystem(), p.namespace(), p.name(), p.version());
                identities.computeIfAbsent(coordinates(identity), k -> new ArrayList<>()).add(new Candidate(p, identity));
            } catch (IllegalArgumentException e) {
                // A malformed candidate only affects its own coordinates.
                try {
                    // A bad version must not make an unrelated purl ecosystem ambiguous.
                    conflicting.add(coordinates(parseIdentity(p.purl(), p.ecosystem(), p.namespace(), p.name(), p.version(), false)));
                } catch (IllegalArgumentException invalidCoordinates) {
                    if (p.ecosystem() != null) conflicting.add(List.of(p.ecosystem(), Objects.toString(p.namespace(), ""), packageName(p.ecosystem(), p.name())));
                }
            }
        }
        return new InventoryIndex(identities, conflicting);
    }

    public static Result resolve(UUID root, List<Node> nodes, List<Edge> edges,
                                 List<Package> inventory, Limits limits) {
        Map<UUID, Node> byId = new LinkedHashMap<>();
        Map<String, Long> refCounts = new HashMap<>();
        nodes.forEach(n -> { byId.put(n.id(), n); if (n.ref() != null) refCounts.merge(n.ref(), 1L, Long::sum); });
        Set<UUID> ambiguous = new HashSet<>();
        nodes.stream().filter(n -> n.ref() != null && refCounts.get(n.ref()) > 1).forEach(n -> ambiguous.add(n.id()));
        Map<UUID, List<Edge>> outgoing = new LinkedHashMap<>();
        Set<String> keys = new LinkedHashSet<>();
        edges.stream().filter(e -> Set.of("DEPENDS_ON", "COMPOSED_OF").contains(e.type()))
                .sorted(Comparator.comparing(Edge::key)).forEach(e -> {
                    keys.add(e.key());
                    if (byId.containsKey(e.source())) outgoing.computeIfAbsent(e.source(), k -> new ArrayList<>()).add(e);
                });
        List<Path> paths = new ArrayList<>();
        Set<Gap> gaps = new LinkedHashSet<>();
        if (!byId.containsKey(root)) {
            gaps.add(new Gap(root, null, "IDENTITY_MISSING"));
        } else {
            walk(root, byId, outgoing, index(inventory), ambiguous, limits, new ArrayList<>(), new ArrayList<>(),
                    paths, gaps, new int[2]);
        }
        return new Result(List.copyOf(paths), Set.copyOf(gaps), Set.copyOf(keys), gaps.isEmpty());
    }

    private static void walk(UUID id, Map<UUID, Node> nodes, Map<UUID, List<Edge>> outgoing,
                             InventoryIndex inventory, Set<UUID> ambiguous, Limits limits, List<Node> chain, List<Edge> via,
                             List<Path> paths, Set<Gap> gaps, int[] visited) {
        Node node = nodes.get(id);
        if (chain.stream().anyMatch(n -> n.id().equals(id))) return; // Path-local cycle guard.
        if (ambiguous.contains(id)) { gaps.add(new Gap(id, node.ref(), "IDENTITY_AMBIGUOUS")); return; }
        if (++visited[0] > limits.nodes()) {
            gaps.add(new Gap(null, null, "TRAVERSAL_LIMIT_REACHED"));
            return;
        }
        chain.add(node);
        if (!via.isEmpty() && node.software()) {
            match(node, inventory, chain, via, paths, gaps, limits);
        }
        for (Edge edge : outgoing.getOrDefault(id, List.of())) {
            if (chain.stream().anyMatch(n -> n.id().equals(edge.target()))) continue;
            if (++visited[1] > limits.edges() || via.size() >= limits.depth() || paths.size() >= limits.paths()) {
                gaps.add(new Gap(null, null, "TRAVERSAL_LIMIT_REACHED"));
                break;
            }
            if (!nodes.containsKey(edge.target())) {
                gaps.add(new Gap(node.id(), edge.targetRef(), "IDENTITY_MISSING"));
                continue;
            }
            via.add(edge);
            walk(edge.target(), nodes, outgoing, inventory, ambiguous, limits, chain, via, paths, gaps, visited);
            via.remove(via.size() - 1);
        }
        chain.remove(chain.size() - 1);
    }

    private static void match(Node node, InventoryIndex inventory, List<Node> chain, List<Edge> via,
                              List<Path> paths, Set<Gap> gaps, Limits limits) {
        Identity wanted;
        try {
            wanted = identity(node.purl(), node.ecosystem(), node.namespace(), node.name(), node.version());
        } catch (IllegalArgumentException e) {
            gaps.add(new Gap(node.id(), Objects.toString(node.ref(), node.id().toString()), e.getMessage()));
            return;
        }
        List<Package> matches = new ArrayList<>();
        boolean conflictingCandidate = inventory.conflicting().contains(coordinates(wanted));
        for (Candidate candidate : inventory.identities().getOrDefault(coordinates(wanted), List.of())) {
            Identity found = candidate.identity();
            if (versionsEqual(wanted.version(), found.version(), wanted.ecosystem())
                    && (blank(node.purl()) || wanted.suffix().equals(found.suffix()))) matches.add(candidate.component());
        }
        if (matches.size() > 1 || conflictingCandidate) {
            gaps.add(new Gap(node.id(), Objects.toString(node.ref(), node.id().toString()), "IDENTITY_AMBIGUOUS"));
        } else if (matches.isEmpty()) {
            gaps.add(new Gap(node.id(), Objects.toString(node.ref(), node.id().toString()), "INVENTORY_MATCH_MISSING"));
        } else if (matches.get(0).active()) {
            if (paths.size() >= limits.paths()) {
                gaps.add(new Gap(null, null, "TRAVERSAL_LIMIT_REACHED"));
                return;
            }
            List<String> refs = chain.stream().map(n -> Objects.toString(n.ref(), n.id().toString())).toList();
            List<String> keys = via.stream().map(Edge::key).toList();
            UUID terminal = matches.get(0).id();
            paths.add(new Path(chain.stream().map(Node::id).toList(), via.stream().map(Edge::id).toList(),
                    refs, keys, terminal, blank(node.purl()) ? "NAME_VERSION" : "PURL_VERSION",
                    fingerprint(keys.stream().map(k -> k.length() + ":" + k).collect(java.util.stream.Collectors.joining()) + "|" + terminal)));
        }
    }

    private static Identity identity(String purl, String ecosystem, String namespace, String name, String version) {
        return parseIdentity(purl, ecosystem, namespace, name, version, true);
    }

    private static Identity parseIdentity(String purl, String ecosystem, String namespace, String name,
                                          String version, boolean requireVersion) {
        String purlVersion = null;
        String suffix = "";
        if (!blank(purl)) {
            if (!purl.startsWith("pkg:")) throw new IllegalArgumentException("IDENTITY_MISSING");
            String body = purl.substring(4);
            int suffixIndex = body.indexOf('?');
            int hashIndex = body.indexOf('#');
            if (suffixIndex < 0 || hashIndex >= 0 && hashIndex < suffixIndex) suffixIndex = hashIndex;
            if (suffixIndex >= 0) { suffix = canonicalSuffix(body.substring(suffixIndex)); body = body.substring(0, suffixIndex); }
            int slash = body.indexOf('/');
            if (slash <= 0) throw new IllegalArgumentException("IDENTITY_MISSING");
            ecosystem = body.substring(0, slash).toLowerCase(Locale.ROOT);
            String coordinate = body.substring(slash + 1);
            int at = coordinate.lastIndexOf('@');
            if (at > 0) { purlVersion = decode(coordinate.substring(at + 1)); coordinate = coordinate.substring(0, at); }
            int lastSlash = coordinate.lastIndexOf('/');
            namespace = lastSlash < 0 ? "" : decode(coordinate.substring(0, lastSlash));
            name = decode(coordinate.substring(lastSlash + 1));
        }
        if (blank(ecosystem) || "unknown".equals(ecosystem) || blank(name)) throw new IllegalArgumentException("IDENTITY_MISSING");
        if (!requireVersion) return new Identity(ecosystem, Objects.toString(namespace, ""), packageName(ecosystem, name), "", suffix);
        if (blank(version) && blank(purlVersion)) throw new IllegalArgumentException("VERSION_MISSING");
        if (!blank(version) && !blank(purlVersion) && !versionsEqual(version, purlVersion, ecosystem)) {
            throw new IllegalArgumentException("VERSION_CONFLICT");
        }
        String effective = blank(purlVersion) ? version.trim() : purlVersion;
        if (Set.of("npm", "cargo", "golang").contains(ecosystem) && !validSemver(effective)) {
            throw new IllegalArgumentException("VERSION_INVALID");
        }
        if ("nuget".equals(ecosystem)
                && !effective.matches("[vV]?\\d+(?:\\.\\d+){0,3}(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?")) {
            throw new IllegalArgumentException("VERSION_INVALID");
        }
        if (Set.of("latest", "*", "RELEASE", "LATEST").contains(effective)) throw new IllegalArgumentException("VERSION_INVALID");
        // Validate even when there are no candidates.
        if (!versionsEqual(effective, effective, ecosystem)) throw new IllegalArgumentException("VERSION_INVALID");
        return new Identity(ecosystem, Objects.toString(namespace, ""), packageName(ecosystem, name), effective, suffix);
    }

    private static String canonicalSuffix(String suffix) {
        int hash = suffix.indexOf('#');
        String subpath = hash < 0 ? "" : decode(suffix.substring(hash));
        String qualifiers = hash < 0 ? suffix : suffix.substring(0, hash);
        if (qualifiers.isEmpty()) return subpath;
        if (!qualifiers.startsWith("?")) throw new IllegalArgumentException("IDENTITY_MISSING");
        var sorted = new TreeMap<String, String>();
        for (String pair : qualifiers.substring(1).split("&")) {
            int equals = pair.indexOf('=');
            if (equals < 1) throw new IllegalArgumentException("IDENTITY_MISSING");
            String key = pair.substring(0, equals).toLowerCase(Locale.ROOT);
            if (sorted.putIfAbsent(key, decode(pair.substring(equals + 1))) != null) throw new IllegalArgumentException("IDENTITY_AMBIGUOUS");
        }
        // Length prefixes avoid collisions when decoded values contain delimiters.
        return sorted.entrySet().stream().map(e -> e.getKey().length() + ":" + e.getKey()
                + e.getValue().length() + ":" + e.getValue()).collect(java.util.stream.Collectors.joining()) + "#" + subpath;
    }

    private static String packageName(String ecosystem, String name) {
        if (name == null) return "";
        return "pypi".equals(ecosystem) ? name.toLowerCase(Locale.ROOT).replaceAll("[-_.]+", "-") : name.trim();
    }

    static boolean versionsEqual(String left, String right, String ecosystem) {
        if (blank(left) || blank(right)) return false;
        // Local/build identifiers are part of exact package identity even if ordering utilities ignore them.
        String lExtra = left.contains("+") ? left.substring(left.indexOf('+')) : "";
        String rExtra = right.contains("+") ? right.substring(right.indexOf('+')) : "";
        if (!lExtra.equals(rExtra)) return false;
        if (Set.of("npm", "cargo", "golang").contains(ecosystem)) {
            // Shared ordering uses Maven's comparator, which folds qualifier case and
            // aliases names such as "final". SemVer exact identity must preserve these.
            String leftPre = prerelease(left);
            String rightPre = prerelease(right);
            if (!leftPre.equals(rightPre)) return false;
        }
        if ("maven".equals(ecosystem) && startsWithV(left) != startsWithV(right)) return false;
        VersionScheme scheme = switch (ecosystem) {
            case "pypi" -> VersionScheme.PEP440;
            case "maven" -> VersionScheme.MAVEN;
            case "npm", "cargo", "golang", "nuget" -> VersionScheme.SEMVER;
            case "deb" -> VersionScheme.DPKG;
            case "rpm" -> VersionScheme.RPM;
            default -> null;
        };
        try { return scheme == null ? left.equals(right) : VersionUtil.compare(left, right, scheme) == 0; }
        catch (IllegalArgumentException e) { return false; }
    }

    private static boolean validSemver(String version) {
        if (!version.matches("[vV]?(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?")) return false;
        String pre = prerelease(version);
        if (!pre.isEmpty()) {
            for (String identifier : pre.substring(1).split("\\.")) {
                if (identifier.matches("\\d+") && identifier.length() > 1 && identifier.startsWith("0")) return false;
            }
        }
        return true;
    }

    private static String prerelease(String version) {
        String core = version.split("\\+", 2)[0];
        int dash = core.indexOf('-');
        return dash < 0 ? "" : core.substring(dash);
    }

    private static boolean startsWithV(String version) {
        return version.startsWith("v") || version.startsWith("V");
    }

    private static String decode(String value) {
        try { return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8); }
        catch (IllegalArgumentException e) { throw new IllegalArgumentException("IDENTITY_MISSING"); }
    }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
    public static String fingerprint(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
