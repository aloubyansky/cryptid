package io.github.aloubyansky.cryptid.bytecode;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What an artifact declares that entry points and instantiation need, read without interpreting:
 * its classes' annotations of interest, its service providers and its main class.
 *
 * @param classes the class declarations, see {@link Analyzer#declarations}
 * @param services provider class names, binary, by service type, from {@code META-INF/services}
 * @param mainClass the binary name of the manifest's {@code Main-Class}, if any
 */
public record ArtifactDeclarations(List<ClassDeclaration> classes, Map<String, List<String>> services,
        Optional<String> mainClass) {

    /** No declarations, e.g. of an artifact that couldn't be read. */
    public static final ArtifactDeclarations NONE = new ArtifactDeclarations(List.of(), Map.of(), Optional.empty());

    /** Copies the collections. */
    public ArtifactDeclarations {
        classes = List.copyOf(classes);
        services = Map.copyOf(services);
    }
}
