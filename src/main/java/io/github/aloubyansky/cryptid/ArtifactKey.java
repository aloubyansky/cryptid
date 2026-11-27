package io.github.aloubyansky.cryptid;

import java.util.Objects;

/**
 * Identifies an artifact apart from its version: group, artifact, classifier and type (GACT).
 *
 * @param groupId the Maven groupId
 * @param artifactId the Maven artifactId
 * @param classifier the classifier, empty if none
 * @param type the type, e.g. {@code jar}
 */
public record ArtifactKey(String groupId, String artifactId, String classifier, String type) {

    /** Normalizes a {@code null} classifier to empty and a {@code null} or empty type to {@code jar}. */
    public ArtifactKey {
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");
        classifier = classifier == null ? "" : classifier;
        type = type == null || type.isEmpty() ? "jar" : type;
    }

    @Override
    public String toString() {
        return groupId + ":" + artifactId + ":" + classifier + ":" + type;
    }
}
