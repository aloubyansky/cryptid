package io.github.aloubyansky.cryptid;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The crypto assets found in a set of artifacts, which a CBOM is written from, with the entry
 * points of the application they belong to.
 */
public final class CryptoInventory {

    private final List<ArtifactAnalysis> artifacts;
    private final List<CryptoAsset> assets;
    private final List<EntryPoint> entryPoints;

    private CryptoInventory(List<ArtifactAnalysis> artifacts, List<CryptoAsset> assets, List<EntryPoint> entryPoints) {
        this.artifacts = List.copyOf(artifacts);
        this.assets = List.copyOf(assets);
        this.entryPoints = List.copyOf(entryPoints);
    }

    /**
     * What analyzing each artifact amounted to.
     *
     * @return one analysis per artifact, in the order of the input
     */
    public List<ArtifactAnalysis> artifacts() {
        return artifacts;
    }

    /**
     * The assets found.
     *
     * @return the assets, one per content, each with its occurrences in all artifacts
     */
    public List<CryptoAsset> assets() {
        return assets;
    }

    /**
     * The application's entry points: those supplied with the input, and those detected.
     *
     * @return the entry points; empty if none were supplied or detected
     */
    public List<EntryPoint> entryPoints() {
        return entryPoints;
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
     * occurrences and dependencies, and the entry points. It is for producers of inventories, such
     * as the analysis itself; users of an inventory don't need it. Not thread-safe; a builder is
     * used once.
     */
    public static final class Builder {

        private final List<ArtifactAnalysis> artifacts = new ArrayList<>();
        private final List<EntryPoint> entryPoints = new ArrayList<>();
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
         * Records an entry point of the application.
         *
         * @param entryPoint the entry point
         * @return this builder
         */
        public Builder entryPoint(EntryPoint entryPoint) {
            check();
            entryPoints.add(entryPoint);
            return this;
        }

        /**
         * Adds another inventory: its artifacts and entry points, and its assets merged into those of equal content,
         * with their occurrences and dependencies.
         *
         * @param other the inventory
         * @return this builder
         */
        public Builder add(CryptoInventory other) {
            check();
            artifacts.addAll(other.artifacts());
            entryPoints.addAll(other.entryPoints());
            return addAssets(other.assets());
        }

        /**
         * Adds assets made by another builder, merged into those of equal content, with their
         * occurrences and dependencies.
         *
         * @param assets the assets; those they depend on or that their cipher suites name should
         *     be among them, or added before
         * @return this builder
         */
        public Builder addAssets(List<CryptoAsset> assets) {
            check();
            final Map<CryptoAsset, CryptoAsset> mapped = new LinkedHashMap<>();
            for (CryptoAsset a : assets) {
                final CryptoAsset mine = map(a, mapped);
                a.occurrences().forEach(mine::addOccurrence);
            }
            for (CryptoAsset a : assets) {
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
            return new CryptoInventory(artifacts, new ArrayList<>(assets.values()), entryPoints);
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
