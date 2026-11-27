package io.github.aloubyansky.cryptid;

/**
 * What analyzing an artifact amounted to.
 *
 * @param artifact the artifact
 * @param outcome whether it was analyzed, its result taken from the cache, or its analysis failed
 * @param classes the number of classes analyzed
 * @param findings the number of findings that produced crypto assets
 * @param failedMethods the number of methods whose bytecode couldn't be interpreted
 * @param failure why the analysis failed, {@code null} unless the outcome is {@link Outcome#FAILED}
 */
public record ArtifactAnalysis(ArtifactCoordinates artifact, Outcome outcome, int classes, int findings, int failedMethods,
        String failure) {

    /** How an artifact's result was obtained. */
    public enum Outcome {
        /** The artifact was analyzed. */
        ANALYZED,
        /** The result of an earlier analysis was reused. */
        CACHED,
        /** The analysis failed; the artifact contributes no assets. */
        FAILED
    }

    /**
     * The analysis of an artifact that failed.
     *
     * @param artifact the artifact
     * @param failure why it failed
     * @return an analysis with no classes, findings or failed methods
     */
    public static ArtifactAnalysis failed(ArtifactCoordinates artifact, String failure) {
        return new ArtifactAnalysis(artifact, Outcome.FAILED, 0, 0, 0, failure);
    }

    /**
     * This analysis with another outcome, e.g. a result reused from the cache.
     *
     * @param outcome the outcome
     * @return the analysis with that outcome
     */
    public ArtifactAnalysis withOutcome(Outcome outcome) {
        return new ArtifactAnalysis(artifact, outcome, classes, findings, failedMethods, failure);
    }
}
