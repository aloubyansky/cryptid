package io.github.aloubyansky.cryptid;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.cliassured.CliAssured;
import org.cliassured.CommandSpec;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.parsers.JsonParser;

/**
 * Helpers for the integration tests, which run the packaged uber-jar as a separate process with
 * CLI Assured and read the CBOM it writes.
 */
final class Cli {

    private Cli() {}

    /**
     * A {@code java -jar <runner jar> args...} command, with stderr merged into stdout. The JAR is
     * the one failsafe passes as {@code cryptid.runner.jar}, so the tests check the tree-shaken
     * uber-jar exactly as it ships.
     *
     * @param args the CLI arguments
     * @return the command, to add expectations to
     */
    static CommandSpec cryptid(String... args) {
        final String jar = System.getProperty("cryptid.runner.jar");
        if (jar == null || !Files.isRegularFile(Path.of(jar))) {
            throw new IllegalStateException("cryptid.runner.jar doesn't point to the runner JAR: " + jar
                    + "; run the integration tests with mvn verify");
        }
        return CliAssured.java().args("-jar", jar).args(args).stderrToStdout();
    }

    /** A CBOM written by the CLI, with its assets indexed. */
    record Cbom(Bom bom, List<Component> assets, Map<String, Set<String>> assetsByComponent) {

        /**
         * Parses a CBOM.
         *
         * @param file the CBOM file
         * @return the parsed CBOM
         * @throws IOException if it can't be read
         * @throws ParseException if it isn't valid CycloneDX
         */
        static Cbom read(Path file) throws IOException, ParseException {
            final Bom bom = new JsonParser().parse(Files.readAllBytes(file));
            final List<Component> assets = bom.getComponents().stream()
                    .filter(c -> c.getType() == Component.Type.CRYPTOGRAPHIC_ASSET)
                    .toList();
            final Set<String> libraries = bom.getComponents().stream()
                    .filter(c -> c.getType() == Component.Type.LIBRARY)
                    .map(Component::getBomRef)
                    .collect(Collectors.toSet());
            final Map<String, Set<String>> links = new HashMap<>();
            for (Dependency d : bom.getDependencies()) {
                if (libraries.contains(d.getRef()) && d.getDependencies() != null) {
                    links.put(d.getRef(),
                            d.getDependencies().stream().map(Dependency::getRef).collect(Collectors.toSet()));
                }
            }
            return new Cbom(bom, assets, links);
        }

        /** The total number of occurrences over all assets. */
        long occurrenceCount() {
            return assets.stream().mapToLong(c -> occurrences(c).size()).sum();
        }

        /** The first asset with this name and an occurrence at this location. */
        Optional<Component> find(String name, String location) {
            return assets.stream()
                    .filter(c -> name.equals(c.getName()))
                    .filter(c -> occurrences(c).stream().anyMatch(o -> location.equals(o.getLocation())))
                    .findFirst();
        }

        /** Whether the component with this bom-ref lists the asset as a dependency. */
        boolean linked(String componentRef, Component asset) {
            return assetsByComponent.getOrDefault(componentRef, Set.of()).contains(asset.getBomRef());
        }

        static List<Occurrence> occurrences(Component asset) {
            return asset.getEvidence() == null || asset.getEvidence().getOccurrences() == null
                    ? List.of()
                    : asset.getEvidence().getOccurrences();
        }
    }
}
