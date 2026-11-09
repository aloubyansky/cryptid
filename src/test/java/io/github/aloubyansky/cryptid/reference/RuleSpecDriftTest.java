package io.github.aloubyansky.cryptid.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Checks the hand-maintained {@code src/main/resources/crypto-api-specs.yaml}, and compares it with
 * sonar-cryptography's rules, from which it was first exported.
 *
 * <p>The file must be canonical: the header below, entries sorted by {@code api} with no duplicate,
 * and the layout {@link RuleSpecExporter#mapper()} writes, so that it reads back unchanged.
 *
 * <p>Against the rules, an API method a rule matches must have an entry; removing one is a decision
 * to make here, not by accident. Entries the rules don't have (our additions) and entries that
 * differ from the rules' (our corrections) are reported without failing, in {@code
 * target/spec-drift-report.txt}, and the rules' export is written to {@code
 * target/crypto-api-specs-exported.yaml} for a diff, e.g. when evaluating a sonar-cryptography
 * upgrade. The file is never rewritten.
 */
class RuleSpecDriftTest {

    static final Path SPECS = Path.of("src/main/resources/crypto-api-specs.yaml");
    private static final Path REPORT = Path.of("target/spec-drift-report.txt");
    private static final Path EXPORTED = Path.of("target/crypto-api-specs-exported.yaml");

    /** The header of the specs file. */
    static final String HEADER = """
            # Crypto API specifications, one entry per API method; see docs/detection-redesign.md.
            # Hand-maintained. First exported from sonar-cryptography 1.7.0's Java detection rules,
            # https://github.com/cbomkit/sonar-cryptography, Copyright (C) 2024 PQCA, Apache License 2.0,
            # and since corrected and extended. Keep entries sorted by api, one per API method;
            # RuleSpecDriftTest checks the file and reports how it differs from the rules.
            """;

    @Test
    void specsAreCanonical() throws Exception {
        final String text = Files.readString(SPECS);
        assertTrue(text.startsWith(HEADER), SPECS + " must start with the header in RuleSpecDriftTest");
        final CryptoApiSpecs specs = RuleSpecExporter.mapper().readValue(SPECS.toFile(), CryptoApiSpecs.class);
        final List<String> problems = new ArrayList<>();
        for (int i = 1; i < specs.apis().size(); i++) {
            final String previous = specs.apis().get(i - 1).api();
            final String api = specs.apis().get(i).api();
            final int order = previous.compareTo(api);
            if (order == 0) {
                problems.add("duplicate: " + api);
            } else if (order > 0) {
                problems.add("out of order: " + api + " after " + previous);
            }
        }
        assertTrue(problems.isEmpty(), SPECS + ":\n  " + String.join("\n  ", problems));
        // the layout is the mapper's, so edits stay reviewable and the file reads back unchanged
        assertEquals(HEADER + RuleSpecExporter.mapper().writeValueAsString(specs), text,
                SPECS + " isn't in the canonical layout; compare with what the mapper writes");
    }

    @Test
    void reportsDriftFromTheRules() throws Exception {
        final RuleSpecExporter.Export export = new RuleSpecExporter().export(SonarCryptographyRules.javaRules());
        // everything the rules say about an API method is the same wherever it appears
        assertTrue(export.report().conflicts().isEmpty(), export.report().summary());

        final Map<String, ApiSpec> ours = byApi(CryptoApiSpecs.load());
        final Map<String, ApiSpec> rules = byApi(export.specs());
        final List<String> missing = new ArrayList<>();
        final List<String> added = new ArrayList<>();
        final List<String> changed = new ArrayList<>();
        rules.forEach((api, spec) -> {
            final ApiSpec own = ours.get(api);
            if (own == null) {
                missing.add(api);
            } else if (!own.equals(spec)) {
                changed.add(api);
            }
        });
        ours.keySet().stream().filter(api -> !rules.containsKey(api)).forEach(added::add);

        final StringBuilder report = new StringBuilder();
        report.append("Specs: ").append(ours.size()).append(" entries; rules of sonar-cryptography ")
                .append(export.specs().source().version()).append(": ").append(rules.size()).append('\n');
        section(report, "Only in the rules", missing);
        section(report, "Only in the specs (additions)", added);
        section(report, "Different from the rules (corrections)", changed);
        Files.createDirectories(REPORT.getParent());
        Files.writeString(REPORT, report.toString());
        Files.writeString(EXPORTED, RuleSpecExporter.yaml(export.specs()));
        System.out.print(report);

        assertTrue(missing.isEmpty(), "API methods of the rules without a spec entry, see " + REPORT + ":\n  "
                + String.join("\n  ", missing));
    }

    private static void section(StringBuilder report, String title, List<String> apis) {
        report.append(title).append(": ").append(apis.size()).append('\n');
        apis.forEach(api -> report.append("  ").append(api).append('\n'));
    }

    private static Map<String, ApiSpec> byApi(CryptoApiSpecs specs) {
        final Map<String, ApiSpec> result = new LinkedHashMap<>();
        for (ApiSpec spec : specs.apis()) {
            result.put(spec.api(), spec);
        }
        return result;
    }
}
