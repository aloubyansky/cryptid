package io.github.aloubyansky.cryptid.detection;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;

/**
 * The path form of an artifact's coordinates, which prefixes the source files of occurrence
 * locations in the CBOM and names the artifact in the analysis's internal keys.
 */
public final class ArtifactPaths {

    private ArtifactPaths() {}

    /**
     * Returns an artifact's path.
     *
     * @param artifact the artifact
     * @return {@code groupId/artifactId/version}, followed by {@code /classifier} if it has one
     */
    public static String of(ArtifactCoordinates artifact) {
        return artifact.groupId() + "/" + artifact.artifactId() + "/" + artifact.version()
                + (artifact.classifier().isEmpty() ? "" : "/" + artifact.classifier());
    }
}
