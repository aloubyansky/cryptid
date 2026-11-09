package io.github.aloubyansky.cryptid.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Keeps {@code src/main/resources/crypto-api-specs.yaml} canonical, and reports how it differs from
 * sonar-cryptography's rules.
 *
 * <p>The specs were bootstrapped from those rules and are now the project's own: they carry
 * corrections and entries for APIs the rules don't cover, so they are no longer expected to equal
 * the export. What this test enforces is only that the file parses and is written in the canonical
 * form {@link RuleSpecExporter#mapper()} produces, so that hand edits stay diffable.
 *
 * <p>The export itself is the opt-in diff tool of
 * {@code docs/detection-redesign.md#when-the-exporter-runs}: every run writes the rules of the
 * sonar-cryptography version on the test classpath to {@code target/crypto-api-specs-exported.yaml}
 * and a comparison with our specs to {@code target/spec-drift-report.txt}, listing the API methods
 * the rules have and we don't, the ones only we have, and the ones whose spec differs. Read it when
 * evaluating a sonar-cryptography upgrade and port what matters by hand; drift never fails the
 * build.
 *
 * <p>{@code -Dspecs.bootstrap=true} overwrites the specs with the export. That discards every hand
 * edit and exists only to start over from a new sonar-cryptography version.
 */
class RuleSpecDriftTest {

    private static final Path SPECS = Path.of("src/main/resources/crypto-api-specs.yaml");
    private static final Path REPORT = Path.of("target/spec-drift-report.txt");
    private static final Path EXPORTED = Path.of("target/crypto-api-specs-exported.yaml");

    @Test
    void specsAreCanonicalAndDriftFromTheRulesIsReported() throws Exception {
        final RuleSpecExporter.Export export = new RuleSpecExporter().export(SonarCryptographyRules.javaRules());
        Files.createDirectories(REPORT.getParent());
        Files.writeString(EXPORTED, RuleSpecExporter.yaml(export.specs()));

        if (Boolean.getBoolean("specs.bootstrap")) {
            Files.writeString(SPECS, RuleSpecExporter.yaml(export.specs()));
            System.out.println("Specs overwritten from the rules: " + SPECS);
        }

        assertTrue(Files.exists(SPECS), SPECS + " is missing; run with -Dspecs.bootstrap=true");
        final CryptoApiSpecs ours = RuleSpecExporter.mapper().readValue(SPECS.toFile(), CryptoApiSpecs.class);
        assertEquals(CryptoApiSpecs.VERSION, ours.specVersion(), SPECS + " has an unexpected format version");

        // the file is the canonical serialization of what it parses to, below its comment header
        final String text = Files.readString(SPECS);
        assertEquals(RuleSpecExporter.mapper().writeValueAsString(ours), body(text),
                SPECS + " is not in canonical form; reserialize it (the body must be what the YAML mapper writes)");

        Files.writeString(REPORT, drift(ours, export));
        System.out.print(drift(ours, export));
    }

    /** The document without the leading {@code #} comment header. */
    private static String body(String text) {
        int start = 0;
        while (start < text.length() && text.charAt(start) == '#') {
            final int nl = text.indexOf('\n', start);
            if (nl < 0) {
                return "";
            }
            start = nl + 1;
        }
        return text.substring(start);
    }

    /** How our specs and the rules' export differ, by API method. */
    private static String drift(CryptoApiSpecs ours, RuleSpecExporter.Export export) {
        final Map<String, ApiSpec> mine = byApi(ours.apis());
        final Map<String, ApiSpec> theirs = byApi(export.specs().apis());
        final List<String> onlyInRules = new ArrayList<>();
        final List<String> onlyInSpecs = new ArrayList<>();
        final List<String> different = new ArrayList<>();
        for (Map.Entry<String, ApiSpec> e : theirs.entrySet()) {
            final ApiSpec ourSpec = mine.get(e.getKey());
            if (ourSpec == null) {
                onlyInRules.add(e.getKey());
            } else if (!ourSpec.equals(e.getValue())) {
                different.add(e.getKey());
            }
        }
        for (String api : mine.keySet()) {
            if (!theirs.containsKey(api)) {
                onlyInSpecs.add(api);
            }
        }
        final StringBuilder sb = new StringBuilder();
        sb.append("Specs: ").append(mine.size()).append(" API methods; sonar-cryptography ")
                .append(export.specs().source().version()).append(": ").append(theirs.size()).append('\n');
        sb.append("Drift: ").append(onlyInRules.size()).append(" only in the rules, ")
                .append(onlyInSpecs.size()).append(" only in our specs, ")
                .append(different.size()).append(" with a different spec\n");
        append(sb, "Only in the rules (port by hand if they matter)", onlyInRules);
        append(sb, "Only in our specs (our own entries and corrections)", onlyInSpecs);
        append(sb, "Different (ours wins; check each on an upgrade)", different);
        sb.append('\n').append(export.report().summary());
        return sb.toString();
    }

    private static void append(StringBuilder sb, String title, List<String> apis) {
        if (apis.isEmpty()) {
            return;
        }
        sb.append('\n').append(title).append(" (").append(apis.size()).append("):\n");
        for (String api : apis) {
            sb.append("  ").append(api).append('\n');
        }
    }

    private static Map<String, ApiSpec> byApi(List<ApiSpec> apis) {
        final Map<String, ApiSpec> map = new TreeMap<>();
        for (ApiSpec spec : apis) {
            map.put(spec.api(), spec);
        }
        return map;
    }
}
