package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import com.prototype.vulnwatch.service.AiBomCorrelationResolver.*;
import com.prototype.vulnwatch.service.AiBomCorrelationResolver.Package;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;

class AiBomCorrelationResolverTest {
    private static final Limits LIMITS = new Limits(16, 100, 100, 100);
    private static UUID id(String value) { return UUID.nameUUIDFromBytes(value.getBytes(StandardCharsets.UTF_8)); }
    private Node model(String ref) { return new Node(id(ref), ref, ref, "", null, "1", null, false); }
    private Node library(String ref, String purl, String version) {
        return new Node(id(ref), ref, "some-lib", "", "pypi", version, purl, true);
    }
    private Edge edge(String from, String to) { return new Edge(id(from + to), id(from), id(to), from, to, "DEPENDS_ON"); }
    private Package pkg(String key, String purl, String version) { return new Package(id(key), "some-lib", "", "pypi", version, purl, true); }
    private Result direct(Node lib, List<Package> packages) {
        return AiBomCorrelationResolver.resolve(id("root"), List.of(model("root"), lib), List.of(edge("root", lib.ref())), packages, LIMITS);
    }
    private void gap(Result r, String reason) { assertTrue(r.gaps().stream().anyMatch(g -> reason.equals(g.reason())), r.gaps().toString()); assertFalse(r.complete()); }

    @Test void directPurlAndPurlOnlyVersionMatch() {
        Result r = direct(library("lib", "pkg:pypi/Some_Lib@1.0", null), List.of(pkg("inventory", "pkg:pypi/some-lib@1.0.0", "1.0")));
        assertTrue(r.complete()); assertEquals(1, r.paths().size());
        assertEquals(List.of(id("root"), id("lib")), r.paths().get(0).components());
        assertEquals("PURL_VERSION", r.paths().get(0).method());
    }
    @Test void explicitEcosystemFallbackMatchesNormalizedVersion() {
        Result r = direct(library("lib", null, "1.0"), List.of(pkg("inventory", "pkg:pypi/some-lib@1.0.0", "1.0.0")));
        assertEquals(1, r.paths().size()); assertEquals("NAME_VERSION", r.paths().get(0).method());
    }
    @Test void threeHopsAndDiamondKeepIndependentOrderedPaths() {
        List<Node> nodes = List.of(model("root"), model("a"), model("b"), model("c"), library("lib", "pkg:pypi/some-lib@1", "1"));
        List<Edge> edges = List.of(edge("root", "a"), edge("root", "b"), edge("a", "c"), edge("b", "c"), edge("c", "lib"));
        var inventory = List.of(pkg("inventory", "pkg:pypi/some-lib@1", "1"));
        Result r = AiBomCorrelationResolver.resolve(id("root"), nodes, edges, inventory, LIMITS);
        assertEquals(2, r.paths().size()); assertTrue(r.complete());
        assertEquals(4, r.paths().get(0).components().size()); assertNotEquals(r.paths().get(0).fingerprint(), r.paths().get(1).fingerprint());
        Result remaining = AiBomCorrelationResolver.resolve(id("root"), nodes, edges.subList(1, edges.size()), inventory, LIMITS);
        assertEquals(1, remaining.paths().size());
        assertEquals(r.paths().get(1).fingerprint(), remaining.paths().get(0).fingerprint());
    }
    @Test void cyclesTerminateWithoutLosingAlternatePaths() {
        Result r = AiBomCorrelationResolver.resolve(id("root"), List.of(model("root"), model("a"), library("lib", "pkg:pypi/some-lib@1", "1")),
                List.of(edge("root", "a"), edge("a", "root"), edge("a", "lib")), List.of(pkg("inventory", "pkg:pypi/some-lib@1", "1")), LIMITS);
        assertTrue(r.complete()); assertEquals(1, r.paths().size());
    }
    @Test void nonDependencyEdgesNeverSupportFindings() {
        Result r = AiBomCorrelationResolver.resolve(id("root"), List.of(model("root"), library("lib", "pkg:pypi/some-lib@1", "1")),
                List.of(new Edge(id("edge"), id("root"), id("lib"), "root", "lib", "TRAINED_ON")),
                List.of(pkg("inventory", "pkg:pypi/some-lib@1", "1")), LIMITS);
        assertTrue(r.complete()); assertTrue(r.paths().isEmpty());
    }
    @Test void absentDocumentNodeCannotBeFollowed() {
        Result r = AiBomCorrelationResolver.resolve(id("root"), List.of(model("root")), List.of(edge("root", "foreign")), List.of(), LIMITS);
        gap(r, "IDENTITY_MISSING"); assertTrue(r.paths().isEmpty());
    }
    @Test void eachTraversalLimitReportsIncompleteCoverage() {
        for (Limits limits : List.of(new Limits(1, 100, 100, 100), new Limits(16, 1, 100, 100),
                new Limits(16, 100, 1, 100), new Limits(16, 100, 100, 1))) {
            Result r = AiBomCorrelationResolver.resolve(id("root"), List.of(model("root"), library("a", "pkg:pypi/some-lib@1", "1"), library("lib", "pkg:pypi/some-lib@1", "1")),
                    List.of(edge("root", "a"), edge("a", "lib")), List.of(pkg("inventory", "pkg:pypi/some-lib@1", "1")), limits);
            gap(r, "TRAVERSAL_LIMIT_REACHED");
        }
    }
    @Test void missingAndConflictingVersionsAreGaps() {
        gap(direct(library("lib", "pkg:pypi/some-lib", null), List.of()), "VERSION_MISSING");
        gap(direct(library("lib", "pkg:pypi/some-lib@1", "2"), List.of()), "VERSION_CONFLICT");
    }
    @Test void malformedVersionsAreRejected() {
        gap(direct(library("lib", "pkg:pypi/some-lib@bad-version", null), List.of()), "VERSION_INVALID");
    }
    @Test void wrongEcosystemNamespaceAndVersionNeverMatch() {
        for (String purl : List.of("pkg:npm/some-lib@1", "pkg:pypi/vendor/some-lib@1", "pkg:pypi/some-lib@2")) {
            var r = direct(library("lib", "pkg:pypi/some-lib@1", "1"), List.of(pkg("inventory", purl, purl.endsWith("@2") ? "2" : "1")));
            assertTrue(r.paths().isEmpty()); gap(r, "INVENTORY_MATCH_MISSING");
        }
    }
    @Test void duplicatesAreAmbiguousEvenIfOnlyOneHasAFinding() {
        var r = direct(library("lib", "pkg:pypi/some-lib@1", "1"), List.of(pkg("one", "pkg:pypi/some-lib@1", "1"), pkg("two", "pkg:pypi/some-lib@1", "1")));
        assertTrue(r.paths().isEmpty()); gap(r, "IDENTITY_AMBIGUOUS");
    }
    @Test void uncertainBranchPreservesOnlyStillAssertedPaths() {
        Node lib = library("lib", "pkg:pypi/some-lib", null);
        var r = direct(lib, List.of());
        assertTrue(r.preserves(List.of("root", "lib"), List.of(edge("root", "lib").key())));
        assertFalse(r.preserves(List.of("root", "removed"), List.of(edge("root", "removed").key())));
    }
    @Test void packageCaseAndBuildMetadataDoNotCollide() {
        var root = model("root");
        var lib = new Node(id("lib"), "lib", "Lib", "Org", "maven", "1", "pkg:maven/Org/Lib@1", true);
        var r = AiBomCorrelationResolver.resolve(root.id(), List.of(root, lib), List.of(edge("root", "lib")),
                List.of(new Package(id("inv"), "lib", "org", "maven", "1", "pkg:maven/org/lib@1", true)), LIMITS);
        assertTrue(r.paths().isEmpty());
        assertFalse(AiBomCorrelationResolver.versionsEqual("1.0+cpu", "1.0+cuda", "pypi"));
    }
    @Test void declaredModelsAreNeverMatchedAsSoftwareFromPurlAlone() {
        var lib = new Node(id("lib"), "lib", "some-lib", "", "pypi", "1", "pkg:pypi/some-lib@1", false);
        var r = direct(lib, List.of(pkg("inventory", "pkg:pypi/some-lib@1", "1")));
        assertTrue(r.complete()); assertTrue(r.paths().isEmpty());
    }

    @Test void duplicateDocumentReferencesAreAmbiguous() {
        Node first = library("lib", "pkg:pypi/some-lib@1", "1");
        Node collision = new Node(id("collision"), "lib", "other", "", "pypi", "1", "pkg:pypi/other@1", true);
        var r = AiBomCorrelationResolver.resolve(id("root"), List.of(model("root"), first, collision), List.of(edge("root", "lib")), List.of(pkg("inventory", "pkg:pypi/some-lib@1", "1")), LIMITS);
        gap(r, "IDENTITY_AMBIGUOUS"); assertTrue(r.paths().isEmpty());
    }
    @Test void cyclesAtDepthBoundAreStillComplete() {
        var r = AiBomCorrelationResolver.resolve(id("root"), List.of(model("root"), model("a")),
                List.of(edge("root", "a"), edge("a", "root")), List.of(), new Limits(1, 10, 10, 10));
        assertTrue(r.complete());
    }

    @Test void exactSemverPrereleaseIdentityDoesNotUseMavenQualifierAliasesOrCaseFolding() {
        for (String ecosystem : List.of("npm", "cargo", "golang")) {
            assertFalse(AiBomCorrelationResolver.versionsEqual("1.0.0-alpha", "1.0.0-ALPHA", ecosystem));
            assertFalse(AiBomCorrelationResolver.versionsEqual("1.0.0-final", "1.0.0", ecosystem));
            assertTrue(AiBomCorrelationResolver.versionsEqual("v1.0.0-alpha.1", "1.0.0-alpha.1", ecosystem));
        }
        assertFalse(AiBomCorrelationResolver.versionsEqual("v1.0", "1.0", "maven"));
    }

    @Test void reorderedPackageUrlQualifiersMatchButConflictingQualifiersDoNot() {
        var r = direct(library("lib", "pkg:pypi/some-lib@1?arch=x86_64&repository_url=https%3A%2F%2Fexample.test", "1"),
                List.of(pkg("inventory", "pkg:pypi/some-lib@1?repository_url=https%3A%2F%2Fexample.test&arch=x86_64", "1")));
        assertEquals(1, r.paths().size());
        var mismatch = direct(library("lib", "pkg:pypi/some-lib@1?arch=x86_64", "1"),
                List.of(pkg("inventory", "pkg:pypi/some-lib@1?arch=arm64", "1")));
        assertTrue(mismatch.paths().isEmpty());
    }

    @Test void invalidSemverCannotEstablishExactPackageSupport() {
        for (String version : List.of("1", "1.0", "01.0.0", "1.0.0-01", "1.0.0-alpha..1", "1.0.0+")) {
            Node lib = new Node(id("lib"), "lib", "some-lib", "", "npm", version, "pkg:npm/some-lib@" + version, true);
            var r = direct(lib, List.of(new Package(id("inventory"), "some-lib", "", "npm", version, "pkg:npm/some-lib@" + version, true)));
            gap(r, "VERSION_INVALID"); assertTrue(r.paths().isEmpty());
        }
    }

    @Test void aMalformedVersionInAnUnrelatedEcosystemDoesNotBlockAValidMatch() {
        var r = direct(library("lib", "pkg:pypi/some-lib@1", "1"), List.of(
                pkg("inventory", "pkg:pypi/some-lib@1", "1"),
                new Package(id("unrelated"), "some-lib", "", "npm", "bad", "pkg:npm/some-lib@bad", true)));
        assertEquals(1, r.paths().size()); assertTrue(r.complete());
    }
}
