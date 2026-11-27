package io.github.aloubyansky.cryptid;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The crypto assets found in a set of artifacts, which a CBOM is written from.
 *
 * @param artifacts what analyzing each artifact amounted to
 * @param assets the assets, one per content, each with its occurrences in all artifacts
 */
public record CryptoInventory(List<ArtifactAnalysis> artifacts, List<CryptoAsset> assets) {

    /** Copies the lists. */
    public CryptoInventory {
        artifacts = List.copyOf(artifacts);
        assets = List.copyOf(assets);
    }

    /**
     * Starts an inventory.
     *
     * @return an empty builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builds an inventory: creates assets, merging those of equal content, and records their
     * occurrences and dependencies. Not thread-safe; a builder is used once.
     */
    public static final class Builder {

        private final List<ArtifactAnalysis> artifacts = new ArrayList<>();
        private final Map<CryptoAsset, CryptoAsset> assets = new LinkedHashMap<>();
        private boolean built;

        private Builder() {}

        /**
         * Returns the asset of a content, creating it on first use.
         *
         * @param name the asset's name
         * @param properties its properties; a protocol's cipher suites must hold assets of this
         *     builder
         * @return the asset of this builder with that content
         */
        public CryptoAsset asset(String name, CryptoAssetProperties properties) {
            check();
            final CryptoAsset candidate = new CryptoAsset(name, properties);
            final CryptoAsset existing = assets.putIfAbsent(candidate, candidate);
            return existing == null ? candidate : existing;
        }

        /**
         * Records an occurrence of an asset; one already recorded is ignored.
         *
         * @param asset an asset of this builder
         * @param location where it occurs
         * @return this builder
         */
        public Builder occurrence(CryptoAsset asset, CodeLocation location) {
            own(asset).addOccurrence(new AssetOccurrence(location));
            return this;
        }

        /**
         * Records that an asset depends on another; a dependency already recorded, or on the asset
         * itself, is ignored.
         *
         * @param asset an asset of this builder
         * @param dependency another asset of this builder
         * @return this builder
         */
        public Builder dependency(CryptoAsset asset, CryptoAsset dependency) {
            own(asset).addDependency(own(dependency));
            return this;
        }

        /**
         * Records what analyzing an artifact amounted to.
         *
         * @param analysis the artifact's analysis
         * @return this builder
         */
        public Builder artifact(ArtifactAnalysis analysis) {
            check();
            artifacts.add(analysis);
            return this;
        }

        /**
         * Adds another inventory: its artifacts, and its assets merged into those of equal content,
         * with their occurrences and dependencies.
         *
         * @param other the inventory
         * @return this builder
         */
        public Builder add(CryptoInventory other) {
            check();
            artifacts.addAll(other.artifacts());
            final Map<CryptoAsset, CryptoAsset> mapped = new LinkedHashMap<>();
            for (CryptoAsset a : other.assets()) {
                final CryptoAsset mine = map(a, mapped);
                a.occurrences().forEach(mine::addOccurrence);
            }
            for (CryptoAsset a : other.assets()) {
                for (CryptoAsset d : a.dependsOn()) {
                    map(a, mapped).addDependency(map(d, mapped));
                }
            }
            return this;
        }

        /** The asset of this builder for an asset of another inventory. */
        private CryptoAsset map(CryptoAsset a, Map<CryptoAsset, CryptoAsset> mapped) {
            final CryptoAsset done = mapped.get(a);
            if (done != null) {
                return done;
            }
            CryptoAssetProperties properties = a.properties();
            if (properties instanceof CryptoAssetProperties.Protocol p && !p.cipherSuites().isEmpty()) {
                final List<CipherSuite> suites = new ArrayList<>();
                for (CipherSuite s : p.cipherSuites()) {
                    suites.add(new CipherSuite(s.name(),
                            s.algorithms().stream().map(x -> map(x, mapped)).toList(), s.identifiers()));
                }
                properties = new CryptoAssetProperties.Protocol(p.type(), p.version(), suites, p.oid());
            }
            final CryptoAsset mine = asset(a.name(), properties);
            mapped.put(a, mine);
            return mine;
        }

        /**
         * Builds the inventory. The builder can't be used afterwards.
         *
         * @return the inventory, with the assets in the order they were first created
         */
        public CryptoInventory build() {
            check();
            built = true;
            return new CryptoInventory(artifacts, new ArrayList<>(assets.values()));
        }

        private CryptoAsset own(CryptoAsset asset) {
            check();
            final CryptoAsset mine = assets.get(asset);
            if (mine != asset) {
                throw new IllegalArgumentException("Not an asset of this builder: " + asset);
            }
            return mine;
        }

        private void check() {
            if (built) {
                throw new IllegalStateException("The inventory was built already");
            }
        }
    }
}
