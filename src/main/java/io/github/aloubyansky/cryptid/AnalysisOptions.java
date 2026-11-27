package io.github.aloubyansky.cryptid;

import java.util.Objects;

/** How to analyze: options that may differ from one analysis to the next. */
public final class AnalysisOptions {

    private final ClasspathScope classpath;
    private final int threads;
    private final boolean rescan;

    private AnalysisOptions(Builder b) {
        this.classpath = b.classpath;
        this.threads = b.threads;
        this.rescan = b.rescan;
    }

    /**
     * The default options.
     *
     * @return supertypes from the dependencies, one thread per available processor, results reused
     */
    public static AnalysisOptions defaults() {
        return builder().build();
    }

    /**
     * Starts options with the defaults.
     *
     * @return a builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Which JARs supertypes are resolved from.
     *
     * @return the scope, {@link ClasspathScope#DEPENDENCIES} by default
     */
    public ClasspathScope classpath() {
        return classpath;
    }

    /**
     * How many threads analyze artifacts.
     *
     * @return at least 1; the available processors by default
     */
    public int threads() {
        return threads;
    }

    /**
     * Whether results of earlier analyses are ignored. Fresh results are still kept.
     *
     * @return {@code true} to analyze every artifact again; {@code false} by default
     */
    public boolean rescan() {
        return rescan;
    }

    /** Builds options. */
    public static final class Builder {

        private ClasspathScope classpath = ClasspathScope.DEPENDENCIES;
        private int threads = Runtime.getRuntime().availableProcessors();
        private boolean rescan;

        private Builder() {}

        /**
         * Sets which JARs supertypes are resolved from.
         *
         * @param classpath the scope
         * @return this builder
         */
        public Builder classpath(ClasspathScope classpath) {
            this.classpath = Objects.requireNonNull(classpath, "classpath");
            return this;
        }

        /**
         * Sets how many threads analyze artifacts.
         *
         * @param threads the number; values below 1 mean 1
         * @return this builder
         */
        public Builder threads(int threads) {
            this.threads = Math.max(1, threads);
            return this;
        }

        /**
         * Sets whether results of earlier analyses are ignored.
         *
         * @param rescan {@code true} to analyze every artifact again
         * @return this builder
         */
        public Builder rescan(boolean rescan) {
            this.rescan = rescan;
            return this;
        }

        /**
         * Builds the options.
         *
         * @return the options
         */
        public AnalysisOptions build() {
            return new AnalysisOptions(this);
        }
    }
}
