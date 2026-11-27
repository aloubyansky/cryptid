package io.github.aloubyansky.cryptid;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * An artifact to analyze: its coordinates, its JAR, what it depends on, and whether it is part of
 * the application rather than a library it uses.
 */
public final class InputArtifact {

    private final ArtifactCoordinates coordinates;
    private final Path jar;
    private final List<ArtifactCoordinates> dependencies;
    private final boolean application;

    private InputArtifact(Builder b) {
        this.coordinates = b.coordinates;
        this.jar = b.jar;
        this.dependencies = b.dependencies;
        this.application = b.application;
    }

    /**
     * Starts an artifact.
     *
     * @param coordinates the artifact's coordinates, which identify it in the results
     * @param jar the artifact's JAR
     * @return a builder, of an artifact with unknown dependencies that isn't part of the
     *     application
     */
    public static Builder builder(ArtifactCoordinates coordinates, Path jar) {
        return new Builder(coordinates, jar);
    }

    /**
     * The artifact's coordinates.
     *
     * @return the coordinates, which identify it in the results
     */
    public ArtifactCoordinates coordinates() {
        return coordinates;
    }

    /**
     * The artifact's JAR.
     *
     * @return the JAR
     */
    public Path jar() {
        return jar;
    }

    /**
     * The artifact's direct dependencies, in the order its classpath lists them. Dependencies
     * that aren't analyzed are ignored. Of a class in several artifacts with different contents,
     * the artifact sees its own copy, else that of its nearest dependency, else that of the first
     * artifact of the analysis.
     *
     * @return the dependencies, or empty if they aren't known, e.g. for an artifact missing from
     *     an SBOM's dependency graph
     */
    public Optional<List<ArtifactCoordinates>> dependencies() {
        return Optional.ofNullable(dependencies);
    }

    /**
     * Whether the artifact is part of the application, rather than a library it uses: the
     * application's entry points are searched for in such artifacts.
     *
     * @return {@code true} for the application's own artifacts; {@code false} by default
     */
    public boolean application() {
        return application;
    }

    @Override
    public String toString() {
        return "InputArtifact[" + coordinates + " " + jar + (application ? ", application" : "") + "]";
    }

    /** Builds an artifact. */
    public static final class Builder {

        private final ArtifactCoordinates coordinates;
        private final Path jar;
        private List<ArtifactCoordinates> dependencies;
        private boolean application;

        private Builder(ArtifactCoordinates coordinates, Path jar) {
            this.coordinates = Objects.requireNonNull(coordinates, "coordinates");
            this.jar = Objects.requireNonNull(jar, "jar");
        }

        /**
         * Sets the artifact's direct dependencies.
         *
         * @param direct the dependencies, in the order its classpath lists them; {@code null} if
         *     not known, the default
         * @return this builder
         */
        public Builder dependencies(List<ArtifactCoordinates> direct) {
            this.dependencies = direct == null ? null : List.copyOf(direct);
            return this;
        }

        /**
         * Sets whether the artifact is part of the application.
         *
         * @param application {@code true} for the application's own artifacts
         * @return this builder
         */
        public Builder application(boolean application) {
            this.application = application;
            return this;
        }

        /**
         * Builds the artifact.
         *
         * @return the artifact
         */
        public InputArtifact build() {
            return new InputArtifact(this);
        }
    }
}
