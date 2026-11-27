package io.github.aloubyansky.cryptid;

/**
 * What analyzing an artifact amounted to.
 *
 * @param artifact the artifact
 * @param classes the number of classes analyzed
 * @param findings the number of findings that produced crypto assets
 * @param failedMethods the number of methods whose bytecode couldn't be interpreted
 */
public record ArtifactAnalysis(ArtifactCoordinates artifact, int classes, int findings, int failedMethods) {}
