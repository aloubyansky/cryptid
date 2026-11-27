package io.github.aloubyansky.cryptid;

import java.util.Objects;
import java.util.Optional;

/**
 * A method something outside the analyzed code calls: a REST resource method, a message handler,
 * a scheduled method, {@code main}. An entry point through which external users interact with the
 * application, such as an HTTP endpoint, is {@linkplain Exposure#EXTERNAL external}.
 *
 * <p>The kind is a name, so that entry-point specs, which are data, can add kinds; the kinds that
 * ship have constants here.
 */
public final class EntryPoint {

    /** An HTTP endpoint, e.g. a JAX-RS or Spring resource method. */
    public static final String HTTP = "http";
    /** A gRPC service method. */
    public static final String GRPC = "grpc";
    /** A WebSocket endpoint. */
    public static final String WEBSOCKET = "websocket";
    /** A servlet's request handler. */
    public static final String SERVLET = "servlet";
    /** A consumer of messages from a broker or a channel. */
    public static final String MESSAGING = "messaging";
    /** A method run on a schedule. */
    public static final String SCHEDULED = "scheduled";
    /** A startup or shutdown hook. */
    public static final String LIFECYCLE = "lifecycle";
    /** An observer of events of the application's own, e.g. CDI's. */
    public static final String OBSERVER = "observer";
    /** A {@code main} method. */
    public static final String MAIN = "main";

    /** Whether external parties interact with the application through an entry point. */
    public enum Exposure {
        /** Called on behalf of external users, e.g. an HTTP endpoint. */
        EXTERNAL,
        /** Called by the application's runtime, e.g. a scheduled method. */
        INTERNAL
    }

    /** Where an entry point comes from. */
    public enum Source {
        /** Found in the application's artifacts by the entry-point specs. */
        DETECTED,
        /** Given by the caller of the analysis, e.g. a Quarkus build. */
        SUPPLIED
    }

    private final MethodId method;
    private final ArtifactCoordinates artifact;
    private final String kind;
    private final Exposure exposure;
    private final String address;
    private final Boolean authenticated;
    private final Source source;

    private EntryPoint(Builder b) {
        this.method = b.method;
        this.artifact = b.artifact;
        this.kind = b.kind;
        this.exposure = b.exposure;
        this.address = b.address;
        this.authenticated = b.authenticated;
        this.source = b.source;
    }

    /**
     * Starts an entry point.
     *
     * @param method the method called
     * @param kind its kind, e.g. {@link #HTTP}
     * @return a builder, of an external entry point supplied by the caller
     */
    public static Builder builder(MethodId method, String kind) {
        return new Builder(method, kind);
    }

    /**
     * The method called.
     *
     * @return the method
     */
    public MethodId method() {
        return method;
    }

    /**
     * The artifact whose copy of the method's class it is, where known: a class can be in several
     * artifacts, e.g. shaded into another.
     *
     * @return the artifact, or empty for any copy, e.g. of an entry point supplied without one
     */
    public Optional<ArtifactCoordinates> artifact() {
        return Optional.ofNullable(artifact);
    }

    /**
     * What kind of entry point it is.
     *
     * @return e.g. {@link #HTTP} or {@link #SCHEDULED}
     */
    public String kind() {
        return kind;
    }

    /**
     * Whether external users interact with the application through it.
     *
     * @return the exposure
     */
    public Exposure exposure() {
        return exposure;
    }

    /**
     * How it is addressed, where the code says, e.g. an HTTP method and path template.
     *
     * @return e.g. {@code POST /realms/{realm}/protocol/openid-connect/token}, or empty
     */
    public Optional<String> address() {
        return Optional.ofNullable(address);
    }

    /**
     * Whether calling it requires authentication, where the code says, e.g. by an annotation.
     * Security configured outside the code isn't known.
     *
     * @return the requirement, or empty if the code doesn't say
     */
    public Optional<Boolean> authenticated() {
        return Optional.ofNullable(authenticated);
    }

    /**
     * Where the entry point comes from.
     *
     * @return detected or supplied
     */
    public Source source() {
        return source;
    }

    @Override
    public String toString() {
        return "EntryPoint[" + kind + " " + method + (address == null ? "" : " " + address) + "]";
    }

    /** Builds an entry point. */
    public static final class Builder {

        private final MethodId method;
        private final String kind;
        private ArtifactCoordinates artifact;
        private Exposure exposure = Exposure.EXTERNAL;
        private String address;
        private Boolean authenticated;
        private Source source = Source.SUPPLIED;

        private Builder(MethodId method, String kind) {
            this.method = Objects.requireNonNull(method, "method");
            this.kind = Objects.requireNonNull(kind, "kind");
        }

        /**
         * Sets the artifact whose copy of the method's class it is.
         *
         * @param artifact the artifact, or {@code null} for any copy, the default
         * @return this builder
         */
        public Builder artifact(ArtifactCoordinates artifact) {
            this.artifact = artifact;
            return this;
        }

        /**
         * Sets the exposure.
         *
         * @param exposure external or internal; {@link Exposure#EXTERNAL} by default
         * @return this builder
         */
        public Builder exposure(Exposure exposure) {
            this.exposure = Objects.requireNonNull(exposure, "exposure");
            return this;
        }

        /**
         * Sets how it is addressed.
         *
         * @param address e.g. an HTTP method and path template, or {@code null} if not known
         * @return this builder
         */
        public Builder address(String address) {
            this.address = address;
            return this;
        }

        /**
         * Sets whether calling it requires authentication.
         *
         * @param authenticated the requirement, or {@code null} if not known
         * @return this builder
         */
        public Builder authenticated(Boolean authenticated) {
            this.authenticated = authenticated;
            return this;
        }

        /**
         * Sets where it comes from.
         *
         * @param source detected or supplied; {@link Source#SUPPLIED} by default
         * @return this builder
         */
        public Builder source(Source source) {
            this.source = Objects.requireNonNull(source, "source");
            return this;
        }

        /**
         * Builds the entry point.
         *
         * @return the entry point
         */
        public EntryPoint build() {
            return new EntryPoint(this);
        }
    }
}
