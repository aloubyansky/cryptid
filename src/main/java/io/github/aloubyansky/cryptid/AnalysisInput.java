package io.github.aloubyansky.cryptid;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * What to analyze: the artifacts, which of them are the application's own ({@link
 * InputArtifact#application()}), and what the caller knows of the application, such as its entry
 * points and the classes it instantiates, e.g. from a Quarkus build.
 */
public final class AnalysisInput {

    private final List<InputArtifact> artifacts;
    private final List<EntryPoint> entryPoints;
    private final Set<String> instantiatedClasses;

    private AnalysisInput(Builder b) {
        this.artifacts = List.copyOf(b.artifacts);
        this.entryPoints = List.copyOf(b.entryPoints);
        this.instantiatedClasses = Set.copyOf(b.instantiatedClasses);
    }

    /**
     * Starts an input.
     *
     * @return an empty builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The artifacts to analyze.
     *
     * @return the artifacts, with distinct coordinates; their order is that of the inventory's
     *     artifacts and assets
     */
    public List<InputArtifact> artifacts() {
        return artifacts;
    }

    /**
     * Entry points the caller supplies, in addition to those the analysis detects.
     *
     * @return the entry points; empty by default
     */
    public List<EntryPoint> entryPoints() {
        return entryPoints;
    }

    /**
     * Classes the caller knows the application instantiates, in addition to those the analysis
     * finds, e.g. the beans a Quarkus build keeps.
     *
     * @return binary class names, e.g. {@code org.acme.Service}; empty by default
     */
    public Set<String> instantiatedClasses() {
        return instantiatedClasses;
    }

    /** Builds an input. */
    public static final class Builder {

        private final List<InputArtifact> artifacts = new ArrayList<>();
        private final List<EntryPoint> entryPoints = new ArrayList<>();
        private final Set<String> instantiatedClasses = new LinkedHashSet<>();

        private Builder() {}

        /**
         * Adds an artifact to analyze.
         *
         * @param artifact the artifact
         * @return this builder
         */
        public Builder artifact(InputArtifact artifact) {
            artifacts.add(Objects.requireNonNull(artifact, "artifact"));
            return this;
        }

        /**
         * Adds artifacts to analyze.
         *
         * @param artifacts the artifacts, in order
         * @return this builder
         */
        public Builder artifacts(List<InputArtifact> artifacts) {
            artifacts.forEach(this::artifact);
            return this;
        }

        /**
         * Adds an entry point the caller knows of.
         *
         * @param entryPoint the entry point
         * @return this builder
         */
        public Builder entryPoint(EntryPoint entryPoint) {
            entryPoints.add(Objects.requireNonNull(entryPoint, "entryPoint"));
            return this;
        }

        /**
         * Adds a class the caller knows the application instantiates.
         *
         * @param className the binary class name
         * @return this builder
         */
        public Builder instantiatedClass(String className) {
            instantiatedClasses.add(Objects.requireNonNull(className, "className"));
            return this;
        }

        /**
         * Builds the input.
         *
         * @return the input
         */
        public AnalysisInput build() {
            return new AnalysisInput(this);
        }
    }
}
