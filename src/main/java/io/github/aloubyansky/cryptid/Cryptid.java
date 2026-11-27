package io.github.aloubyansky.cryptid;

import io.github.aloubyansky.cryptid.analysis.AnalysisRun;
import io.github.aloubyansky.cryptid.scan.BytecodeScanner;
import io.github.aloubyansky.cryptid.spec.EntryPointSpecs;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import org.jboss.logging.Logger;

/**
 * Analyzes the bytecode of artifacts for cryptography and returns the {@link CryptoInventory} of
 * what they use.
 *
 * <p>An instance holds what lasts across analyses: the loaded crypto API specs and, if given, the
 * cache directory where each artifact's result is kept for later analyses. The cache's format and
 * keys are the library's: a result is reused only by an analysis with the same build of the
 * library, and the same artifacts, JARs and dependencies.
 *
 * <p>Thread-safe; analyses may run concurrently, though each uses its own threads.
 */
public final class Cryptid {

    private static final Logger log = Logger.getLogger(Cryptid.class);

    private final BytecodeScanner scanner;
    private final EntryPointSpecs entryPointSpecs;
    private final Path cacheDirectory;

    private Cryptid(Builder b) {
        this.scanner = new BytecodeScanner();
        try {
            this.entryPointSpecs = EntryPointSpecs.load();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load the entry-point specs", e);
        }
        this.cacheDirectory = b.cacheDirectory;
        log.infof("Loaded %s", scanner.detection());
    }

    /**
     * Starts configuring an instance.
     *
     * @return a builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Analyzes artifacts.
     *
     * @param input the artifacts, with distinct coordinates, whose order is that of the
     *     inventory's artifacts and assets, and what the caller knows of the application
     * @param options how to analyze
     * @return the inventory: an analysis for every artifact, the assets found in them, merged by
     *     content, and the application's entry points; an artifact whose analysis failed has a
     *     {@link ArtifactAnalysis.Outcome#FAILED} analysis and contributes no assets
     * @throws IllegalArgumentException if two artifacts have the same coordinates
     * @throws UncheckedIOException if the cache directory can't be used
     */
    public CryptoInventory analyze(AnalysisInput input, AnalysisOptions options) {
        try {
            return new AnalysisRun(scanner, entryPointSpecs, cacheDirectory, options, input).run();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Configures an instance. */
    public static final class Builder {

        private Path cacheDirectory;

        private Builder() {}

        /**
         * Sets the directory to keep each artifact's result in, for later analyses to reuse.
         *
         * @param dir the directory, created if missing; {@code null} keeps nothing
         * @return this builder
         */
        public Builder cacheDirectory(Path dir) {
            this.cacheDirectory = dir;
            return this;
        }

        /**
         * Creates the instance, loading the crypto API specs.
         *
         * @return the instance
         * @throws IllegalStateException if the specs can't be loaded
         */
        public Cryptid build() {
            return new Cryptid(this);
        }
    }
}
