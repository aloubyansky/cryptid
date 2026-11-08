package org.acme.cbom;

import static org.acme.cbom.Cli.cbomGenerator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs the packaged uber-jar on the Keycloak 26.8.2 SBOM, as a user would, and checks the CBOM it
 * writes.
 *
 * <p>Tagged {@code e2e} and excluded from the default build: it resolves 548 JARs from the
 * configured Maven repositories (Maven Central on first use), takes about half a minute and needs
 * several GB of heap (the JVM default, a quarter of the RAM, is enough on a 32 GB machine). Run it
 * with {@code mvn verify -Pe2e}.
 *
 * <p>The assertions check facts that should stay stable as the engine improves: every artifact
 * analyzed, values resolved across JARs and through interfaces where Keycloak chooses them, assets
 * linked to the components they're located in, and well-formed occurrences. Totals are checked as
 * lower bounds only.
 */
@Tag("e2e")
class KeycloakEndToEndIT {

    private static final String SBOM = "src/test/resources/keycloak-26.8.2.zip.cdx.json";
    private static final String SERVICES = "pkg:maven/org.keycloak/keycloak-services@26.8.2";

    @Test
    void generatesCbomForKeycloak(@TempDir Path tmp) throws Exception {
        final Path output = tmp.resolve("cbom.json");
        cbomGenerator(SBOM, "-o", output.toString(), "--work-dir", tmp.resolve("work").toString())
                .then()
                    .stdout()
                        .hasLinesContaining("Resolved 548 of 548 artifacts", "Analyzed 548 artifacts", ", 0 failed")
                        .doesNotHaveLinesContaining("Exception", "ERROR")
                    .exitCodeIs(0)
                .execute(Duration.ofMinutes(20))
                .assertSuccess();

        final Cli.Cbom cbom = Cli.Cbom.read(output);
        assertEquals("pkg:maven/org.keycloak/keycloak-quarkus-dist@26.8.2?type=zip",
                cbom.bom().getMetadata().getComponent().getPurl());
        assertTrue(cbom.assets().size() >= 700, "crypto assets: " + cbom.assets().size());
        assertTrue(cbom.occurrenceCount() >= 2400, "occurrences: " + cbom.occurrenceCount());
        assertTrue(cbom.assetsByComponent().size() >= 70, "components with assets: " + cbom.assetsByComponent().size());

        // every occurrence is located in an artifact (groupId/artifactId/version/...), and carries no
        // placeholder positions: bytecode has no column offsets, and some JARs no line tables
        for (Component asset : cbom.assets()) {
            for (Occurrence o : Cli.Cbom.occurrences(asset)) {
                assertTrue(o.getLocation().split("/").length > 3, "location: " + o.getLocation());
                assertTrue(o.getLine() == null || o.getLine() > 0, "line: " + o.getLine() + " at " + o.getLocation());
                assertNull(o.getOffset(), "offset at " + o.getLocation());
            }
        }

        // a value passed across JARs: keycloak-services passes "SHA1" to keycloak-core's
        // HashUtils.hash, which calls MessageDigest.getInstance; reported where it is chosen
        final Component sha1 = cbom.find("SHA-1", "org.keycloak/keycloak-services/26.8.2/org/keycloak/services/util/DPoPUtil.java")
                .orElseThrow(() -> new AssertionError("SHA-1 at DPoPUtil not found"));
        assertTrue(cbom.linked(SERVICES, sha1), "SHA-1 at DPoPUtil isn't linked to keycloak-services");

        // a value passed through an interface: KeyUtils calls the CryptoProvider SPI, whose
        // implementations create the key pair generator
        assertTrue(cbom.find("RSA-2048", "org.keycloak/keycloak-common/26.8.2/org/keycloak/common/util/KeyUtils.java").isPresent(),
                "RSA-2048 at KeyUtils not found");
    }
}
