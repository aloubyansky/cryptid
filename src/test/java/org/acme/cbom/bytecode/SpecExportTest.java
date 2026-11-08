package org.acme.cbom.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.acme.cbom.spec.ApiSpecs;
import org.junit.jupiter.api.Test;

/**
 * Keeps {@code src/main/resources/crypto-api-specs.yaml} in sync with sonar-cryptography's rules
 * while the specs are bootstrapped from them: the test fails when the exported specs differ from
 * the file. Run with {@code -Dspecs.update=true} to rewrite it, e.g. after upgrading
 * sonar-cryptography. The export report is written to {@code target/spec-export-report.txt}.
 */
class SpecExportTest {

    private static final Path SPECS = Path.of("src/main/resources/crypto-api-specs.yaml");
    private static final Path REPORT = Path.of("target/spec-export-report.txt");

    @Test
    void specsMatchTheRules() throws Exception {
        final SpecExporter.Export export = new SpecExporter().export(Translation.javaRules());
        final String yaml = SpecExporter.yaml(export.specs());
        Files.createDirectories(REPORT.getParent());
        Files.writeString(REPORT, export.report().summary());
        System.out.print(export.report().summary());

        // everything a rule says about its API method is the same wherever the method appears
        assertTrue(export.report().conflicts().isEmpty(), export.report().summary());

        if (Boolean.getBoolean("specs.update")) {
            Files.writeString(SPECS, yaml);
            System.out.println("Specs written to " + SPECS);
            return;
        }
        assertTrue(Files.exists(SPECS), SPECS + " is missing; run with -Dspecs.update=true");
        assertTrue(yaml.equals(Files.readString(SPECS)),
                SPECS + " differs from the rules; run with -Dspecs.update=true to rewrite it");
        // the file reads back into the same specs
        final ApiSpecs read = SpecExporter.mapper().readValue(SPECS.toFile(), ApiSpecs.class);
        assertEquals(export.specs().apis().size(), read.apis().size());
        for (int i = 0; i < read.apis().size(); i++) {
            assertEquals(export.specs().apis().get(i), read.apis().get(i), "entry " + i);
        }
        assertEquals(export.specs(), read);
    }
}
