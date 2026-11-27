package io.github.aloubyansky.cryptid;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    private static List<InputArtifact> inputs() {
        return List.of(new InputArtifact(LIB, lib, List.of()), new InputArtifact(APP, app, List.of(LIB)));
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
                List.of(new InputArtifact(LIB, lib, List.of()), new InputArtifact(APP, app, null)), AnalysisOptions.defaults());
        assertTrue(fourth.artifacts().stream().allMatch(a -> a.outcome() == Outcome.ANALYZED), fourth.artifacts().toString());
    }

    @Test
    void reportsAFailedArtifact(@TempDir Path dir) throws Exception {
        final Path broken = Files.writeString(dir.resolve("broken.jar"), "not a JAR");
        final ArtifactCoordinates coords = ArtifactCoordinates.jar("org.acme", "broken", "1.0");
        final CryptoInventory inventory = cryptid.analyze(
                List.of(new InputArtifact(coords, broken, List.of()), new InputArtifact(LIB, lib, List.of())),
                AnalysisOptions.defaults());
        final ArtifactAnalysis failed = inventory.artifacts().get(0);
        assertEquals(Outcome.FAILED, failed.outcome());
        assertNotNull(failed.failure());
        assertEquals(Outcome.ANALYZED, inventory.artifacts().get(1).outcome());
    }

    @Test
    void rejectsDuplicateCoordinates() {
        assertThrows(IllegalArgumentException.class, () -> cryptid.analyze(
                List.of(new InputArtifact(LIB, lib, null), new InputArtifact(LIB, app, null)), AnalysisOptions.defaults()));
    }
}
