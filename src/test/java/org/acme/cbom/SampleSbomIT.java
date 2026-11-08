package org.acme.cbom;

import static org.acme.cbom.Cli.cbomGenerator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.cyclonedx.model.Component;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs the packaged uber-jar on {@code src/test/resources/sample-sbom.json}: Bouncy Castle,
 * commons-codec and netty (with and without a classifier), an application component that isn't
 * published, and an npm package. Takes a few seconds once the JARs are in the local repository.
 */
class SampleSbomIT {

    private static final String SBOM = "src/test/resources/sample-sbom.json";
    private static final String BCPROV = "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78.1?type=jar";
    private static final String CODEC = "pkg:maven/commons-codec/commons-codec@1.17.1?type=jar";
    private static final Duration TIMEOUT = Duration.ofMinutes(5);

    @Test
    void generatesCbom(@TempDir Path tmp) throws Exception {
        final Path output = tmp.resolve("cbom.json");
        cbomGenerator(SBOM, "-o", output.toString(), "--work-dir", tmp.resolve("work").toString())
                .then()
                    .stdout()
                        .hasLinesContaining(
                                "Found 5 Maven components",
                                // sample-app isn't published
                                "Resolved 4 of 5 artifacts",
                                "Loaded 515 crypto API specs",
                                "Analyzed 4 artifacts",
                                ", 0 failed",
                                "2 of 4 analyzed components contain cryptographic assets")
                        .doesNotHaveLinesContaining("Exception", "ERROR")
                    .exitCodeIs(0)
                .execute(TIMEOUT)
                .assertSuccess();

        final Cli.Cbom cbom = Cli.Cbom.read(output);
        assertEquals("pkg:maven/org.acme/sample-app@1.0.0?type=jar",
                cbom.bom().getMetadata().getComponent().getPurl());
        assertTrue(cbom.assets().size() >= 200, "crypto assets: " + cbom.assets().size());
        // the tool versions come from the build, not from the uber-jar's merged manifest
        final Map<String, String> tools = new HashMap<>();
        cbom.bom().getMetadata().getToolChoice().getComponents().forEach(t -> tools.put(t.getName(), t.getVersion()));
        assertEquals(Map.of("cbom-generator", BuildInfo.VERSION, "sonar-cryptography", BuildInfo.SONAR_CRYPTOGRAPHY_VERSION), tools);
        assertTrue(BuildInfo.SONAR_CRYPTOGRAPHY_VERSION.matches("\\d+\\.\\d+\\.\\d+.*"), BuildInfo.SONAR_CRYPTOGRAPHY_VERSION);
        assertEquals(Set.of(BCPROV, CODEC), cbom.assetsByComponent().keySet());

        // an algorithm chosen by a constructor, in a JAR without line tables: no line
        final Component aes = cbom.find("AES", "org.bouncycastle/bcprov-jdk18on/1.78.1/org/bouncycastle/crypto/engines/AESEngine.java")
                .orElseThrow(() -> new AssertionError("AES at AESEngine not found"));
        assertTrue(cbom.linked(BCPROV, aes), "AES at AESEngine isn't linked to bcprov");

        // a JCA name passed as a constant to MessageDigest.getInstance, with its line
        final Component sha256 = cbom.find("SHA-256", "commons-codec/commons-codec/1.17.1/org/apache/commons/codec/digest/Sha2Crypt.java")
                .orElseThrow(() -> new AssertionError("SHA-256 at Sha2Crypt not found"));
        assertTrue(cbom.linked(CODEC, sha256), "SHA-256 at Sha2Crypt isn't linked to commons-codec");
        assertTrue(Cli.Cbom.occurrences(sha256).stream().anyMatch(o -> Integer.valueOf(114).equals(o.getLine())),
                "SHA-256 at Sha2Crypt.java:114 not found");
    }

    @Test
    void reusesWorkDirectoryUnlessRescan(@TempDir Path tmp) throws Exception {
        final String work = tmp.resolve("work").toString();
        cbomGenerator(SBOM, "-o", tmp.resolve("first.json").toString(), "--work-dir", work)
                .then().stdout().hasLinesContaining("0 reused from the work directory").exitCodeIs(0)
                .execute(TIMEOUT).assertSuccess();
        cbomGenerator(SBOM, "-o", tmp.resolve("second.json").toString(), "--work-dir", work)
                .then().stdout().hasLinesContaining("Analyzed 0 artifacts (0 classes), 4 reused from the work directory")
                    .exitCodeIs(0)
                .execute(TIMEOUT).assertSuccess();
        cbomGenerator(SBOM, "-o", tmp.resolve("third.json").toString(), "--work-dir", work, "--rescan")
                .then().stdout().hasLinesContaining("Analyzed 4 artifacts", "0 reused from the work directory")
                    .exitCodeIs(0)
                .execute(TIMEOUT).assertSuccess();

        // the reused per-artifact results assemble into the same CBOM
        assertEquals(Cli.Cbom.read(tmp.resolve("first.json")).occurrenceCount(),
                Cli.Cbom.read(tmp.resolve("second.json")).occurrenceCount());
    }

    @Test
    void failsOnMissingSbom(@TempDir Path tmp) {
        final Path output = tmp.resolve("cbom.json");
        cbomGenerator(tmp.resolve("missing.json").toString(), "-o", output.toString())
                .then()
                    .stdout().hasLinesContaining("Failed to parse SBOM")
                    .exitCodeIs(1)
                .execute(TIMEOUT)
                .assertSuccess();
        assertTrue(Files.notExists(output), "no CBOM is written");
    }
}
