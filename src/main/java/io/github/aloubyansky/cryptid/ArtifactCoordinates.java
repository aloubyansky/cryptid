package io.github.aloubyansky.cryptid;

import java.util.Objects;

/**
 * The Maven coordinates of an analyzed artifact: its {@link ArtifactKey key} and version.
 *
 * @param groupId the Maven groupId
 * @param artifactId the Maven artifactId
 * @param classifier the classifier, empty if none
 * @param type the type, e.g. {@code jar}
 * @param version the version
 */
public record ArtifactCoordinates(String groupId, String artifactId, String classifier, String type, String version) {

    /** Normalizes a {@code null} classifier to empty and a {@code null} or empty type to {@code jar}. */
    public ArtifactCoordinates {
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");
        Objects.requireNonNull(version, "version");
        classifier = classifier == null ? "" : classifier;
        type = type == null || type.isEmpty() ? "jar" : type;
    }

    /**
     * Coordinates of a JAR without a classifier.
     *
     * @param groupId the Maven groupId
     * @param artifactId the Maven artifactId
     * @param version the version
     * @return the coordinates
     */
    public static ArtifactCoordinates jar(String groupId, String artifactId, String version) {
        return new ArtifactCoordinates(groupId, artifactId, "", "jar", version);
    }

    /**
     * The artifact's identity apart from its version.
     *
     * @return the group, artifact, classifier and type
     */
    public ArtifactKey key() {
        return new ArtifactKey(groupId, artifactId, classifier, type);
    }

    @Override
    public String toString() {
        return groupId + ":" + artifactId + ":" + classifier + ":" + type + ":" + version;
    }
}
