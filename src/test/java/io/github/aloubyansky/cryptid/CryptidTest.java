package io.github.aloubyansky.cryptid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.ArtifactAnalysis.Outcome;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CryptidTest {

    private static final ArtifactCoordinates LIB = ArtifactCoordinates.jar("org.acme", "lib", "1.0");
    private static final ArtifactCoordinates APP = ArtifactCoordinates.jar("org.acme", "app", "1.0");

    @TempDir
    static Path jars;
    static Path lib;
    static Path app;
    static Cryptid cryptid;

    @BeforeAll
    static void compile() throws Exception {
        lib = TestJars.compile(jars, "lib", Map.of("org/acme/lib/Digests.java", """
                package org.acme.lib;
                import java.security.MessageDigest;
                public class Digests {
                    public static MessageDigest digest(String alg) throws Exception {
                        return MessageDigest.getInstance(alg);
                    }
                }
                """), null);
        app = TestJars.compile(jars, "app", Map.of("org/acme/app/App.java", """
                package org.acme.app;
                import org.acme.lib.Digests;
                public class App {
                    public void run() throws Exception {
                        Digests.digest("SHA-256");
                    }
                }
                """), lib);
        cryptid = Cryptid.builder().build();
    }

    private static AnalysisInput input(InputArtifact... artifacts) {
        return AnalysisInput.builder().artifacts(List.of(artifacts)).build();
    }

    private static AnalysisInput inputs() {
        return input(InputArtifact.builder(LIB, lib).dependencies(List.of()).build(),
                InputArtifact.builder(APP, app).dependencies(List.of(LIB)).build());
    }

    @Test
    void locatesAValuePassedInAtItsCaller() {
        final CryptoInventory inventory = cryptid.analyze(inputs(), AnalysisOptions.defaults());
        assertEquals(List.of(LIB, APP), inventory.artifacts().stream().map(ArtifactAnalysis::artifact).toList());
        assertTrue(inventory.artifacts().stream().allMatch(a -> a.outcome() == Outcome.ANALYZED), inventory.artifacts().toString());
        final CryptoAsset sha = inventory.assets().stream().filter(a -> a.name().equals("SHA256") || a.name().equals("SHA-256"))
                .findFirst().orElseThrow(() -> new AssertionError(inventory.assets()));
        final CodeLocation at = sha.occurrences().get(0).location();
        assertEquals(APP, at.artifact());
        assertEquals(new MethodId("org.acme.app.App", "run", "()V"), at.method());
        assertEquals("org.acme.lib.Digests", at.invokedMethod().className());
    }

    @Test
    void reusesCachedResultsUnlessRescan(@TempDir Path cache) {
        final Cryptid cached = Cryptid.builder().cacheDirectory(cache).build();
        final CryptoInventory first = cached.analyze(inputs(), AnalysisOptions.defaults());
        final CryptoInventory second = cached.analyze(inputs(), AnalysisOptions.defaults());
        assertTrue(second.artifacts().stream().allMatch(a -> a.outcome() == Outcome.CACHED), second.artifacts().toString());
        assertEquals(first.assets(), second.assets());
        for (int i = 0; i < first.assets().size(); i++) {
            assertEquals(first.assets().get(i).occurrences(), second.assets().get(i).occurrences());
        }
        final CryptoInventory third = cached.analyze(inputs(), AnalysisOptions.builder().rescan(true).build());
        assertTrue(third.artifacts().stream().allMatch(a -> a.outcome() == Outcome.ANALYZED), third.artifacts().toString());
        // other dependencies don't reuse them
        final CryptoInventory fourth = cached.analyze(
                input(InputArtifact.builder(LIB, lib).dependencies(List.of()).build(), InputArtifact.builder(APP, app).build()),
                AnalysisOptions.defaults());
        assertTrue(fourth.artifacts().stream().allMatch(a -> a.outcome() == Outcome.ANALYZED), fourth.artifacts().toString());
    }

    @Test
    void reportsAFailedArtifact(@TempDir Path dir) throws Exception {
        final Path broken = Files.writeString(dir.resolve("broken.jar"), "not a JAR");
        final ArtifactCoordinates coords = ArtifactCoordinates.jar("org.acme", "broken", "1.0");
        final CryptoInventory inventory = cryptid.analyze(
                input(InputArtifact.builder(coords, broken).build(), InputArtifact.builder(LIB, lib).build()),
                AnalysisOptions.defaults());
        final ArtifactAnalysis failed = inventory.artifacts().get(0);
        assertEquals(Outcome.FAILED, failed.outcome());
        assertNotNull(failed.failure());
        assertEquals(Outcome.ANALYZED, inventory.artifacts().get(1).outcome());
    }

    @Test
    void rejectsDuplicateCoordinates() {
        assertThrows(IllegalArgumentException.class, () -> cryptid.analyze(
                input(InputArtifact.builder(LIB, lib).build(), InputArtifact.builder(LIB, app).build()), AnalysisOptions.defaults()));
    }

    @Test
    void keepsSuppliedEntryPointsAndLeavesReachabilityUnknown() {
        final EntryPoint run = EntryPoint.builder(new MethodId("org.acme.app.App", "run", "()V"), EntryPoint.HTTP)
                .address("GET /run")
                .build();
        final CryptoInventory inventory = cryptid.analyze(AnalysisInput.builder()
                        .artifacts(inputs().artifacts())
                        .entryPoint(run)
                        .instantiatedClass("org.acme.app.App")
                        .build(),
                AnalysisOptions.defaults());
        assertEquals(List.of(run), inventory.entryPoints());
        assertEquals(EntryPoint.Source.SUPPLIED, run.source());
        assertEquals(EntryPoint.Exposure.EXTERNAL, run.exposure());
        assertTrue(run.authenticated().isEmpty());
        for (CryptoAsset a : inventory.assets()) {
            for (AssetOccurrence o : a.occurrences()) {
                assertEquals(AssetOccurrence.Reachability.UNKNOWN, o.reachability());
                assertEquals(List.of(), o.reachedBy());
            }
        }
    }

    @Test
    void inputArtifactsDefaultToUnknownDependenciesOutsideTheApplication() {
        final InputArtifact a = InputArtifact.builder(LIB, lib).build();
        assertTrue(a.dependencies().isEmpty());
        assertFalse(a.application());
        assertEquals(List.of(), InputArtifact.builder(LIB, lib).dependencies(List.of()).build().dependencies().orElseThrow());
        assertTrue(InputArtifact.builder(APP, app).application(true).build().application());
    }
}
