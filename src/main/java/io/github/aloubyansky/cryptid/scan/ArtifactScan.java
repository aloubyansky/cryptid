package io.github.aloubyansky.cryptid.scan;

import io.github.aloubyansky.cryptid.ArtifactAnalysis;
import io.github.aloubyansky.cryptid.CryptoAsset;
import java.util.List;

/**
 * The result of scanning one JAR: what scanning it amounted to, and the assets found in it. The
 * assets' occurrences may be in other artifacts, where callers pass values in, so this isn't an
 * inventory of the artifact; the inventory of an analysis merges these.
 *
 * @param analysis what scanning the JAR amounted to
 * @param assets the assets found, linked to each other
 */
public record ArtifactScan(ArtifactAnalysis analysis, List<CryptoAsset> assets) {

    /** Copies the assets. */
    public ArtifactScan {
        assets = List.copyOf(assets);
    }
}
