package org.acme.cbom;

import static org.acme.cbom.Cli.cbomGenerator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs the uber-jar several times on the same input and checks that the CBOMs have the same
 * content. Each run is a new JVM, so this catches iteration orders that vary between JVMs, such as
 * {@code Set.of}'s. The input is wildfly-elytron-x500-cert, where a key size field holds one of
 * several constants: its asset used to differ between runs.
 *
 * <p>Random parts are normalized away: bom-refs, UUIDs embedded in asset names, and the timestamp.
 */
class ReproducibilityIT {

    private static final String SBOM = "src/test/resources/wildfly-x500-cert-sbom.json";
    private static final int RUNS = 3;
    private static final Pattern UUID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final ObjectMapper JSON =
            new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    @Test
    void sameInputGivesSameCbom(@TempDir Path tmp) throws Exception {
        List<String> first = null;
        for (int i = 0; i < RUNS; i++) {
            final Path output = tmp.resolve("cbom-" + i + ".json");
            // a fresh work directory each time, so every run analyzes
            cbomGenerator(SBOM, "-o", output.toString(), "--work-dir", tmp.resolve("work-" + i).toString())
                    .then().stdout().hasLinesContaining(", 0 failed").exitCodeIs(0)
                    .execute(Duration.ofMinutes(5)).assertSuccess();
            final List<String> content = canonical(output);
            if (first == null) {
                assertFalse(content.isEmpty(), "no crypto assets found");
                first = content;
            } else {
                assertEquals(String.join("\n", first), String.join("\n", content), "run " + (i + 1) + " differs from run 1");
            }
        }
    }

    /**
     * The CBOM's assets and links as sorted lines, with random identifiers replaced: each asset as
     * JSON with sorted keys and without bom-ref, each link as {@code component -> asset name}.
     */
    private static List<String> canonical(Path cbom) throws Exception {
        final JsonNode bom = JSON.readTree(cbom.toFile());
        final Map<String, String> names = new HashMap<>();
        final List<String> lines = new ArrayList<>();
        for (JsonNode c : bom.path("components")) {
            if (!"cryptographic-asset".equals(c.path("type").asText())) {
                continue;
            }
            final ObjectNode asset = c.deepCopy();
            final String name = UUID.matcher(asset.path("name").asText()).replaceAll("<uuid>");
            names.put(asset.path("bom-ref").asText(), name);
            asset.remove("bom-ref");
            asset.put("name", name);
            lines.add(UUID.matcher(JSON.writeValueAsString(JSON.treeToValue(asset, Object.class))).replaceAll("<uuid>"));
        }
        for (JsonNode d : bom.path("dependencies")) {
            final String from = names.getOrDefault(d.path("ref").asText(), d.path("ref").asText());
            for (JsonNode to : d.path("dependsOn")) {
                // dependency entries can name a ref that isn't a component (a known issue), so
                // UUIDs left after the name mapping are normalized too
                lines.add(UUID.matcher("link " + from + " -> " + names.getOrDefault(to.asText(), to.asText()))
                        .replaceAll("<uuid>"));
            }
        }
        lines.sort(null);
        return lines;
    }
}
