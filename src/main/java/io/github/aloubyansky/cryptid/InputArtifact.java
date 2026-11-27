package io.github.aloubyansky.cryptid;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * An artifact to analyze: its coordinates, its JAR, and what it depends on.
 *
 * @param coordinates the artifact's coordinates, which identify it in the results
 * @param jar the artifact's JAR
 * @param dependencies the artifact's direct dependencies, in the order its classpath lists them;
 *     {@code null} if not known, e.g. for an artifact missing from an SBOM's dependency graph.
 *     Dependencies that aren't analyzed are ignored. Of a class in several artifacts with
 *     different contents, the artifact sees its own copy, else that of its nearest dependency,
 *     else that of the first artifact of the analysis.
 */
public record InputArtifact(ArtifactCoordinates coordinates, Path jar, List<ArtifactCoordinates> dependencies) {

    /** Checks the coordinates and JAR, and copies the dependencies. */
    public InputArtifact {
        Objects.requireNonNull(coordinates, "coordinates");
        Objects.requireNonNull(jar, "jar");
        dependencies = dependencies == null ? null : List.copyOf(dependencies);
    }
}
