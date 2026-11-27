package io.github.aloubyansky.cryptid;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * A cryptographic asset: what it is, where it occurs, and the assets it depends on, e.g. an RSA-PSS
 * signature on its SHA-256 digest. Assets are identified by their content, name and properties: two
 * assets with equal content are equal, wherever they occur.
 *
 * <p>Assets are created by a {@link CryptoInventory.Builder}, which merges assets of equal content
 * and links them; once built, an asset doesn't change.
 */
public final class CryptoAsset {

    private final String name;
    private final CryptoAssetProperties properties;
    private final List<AssetOccurrence> occurrences = new ArrayList<>();
    private final List<CryptoAsset> dependsOn = new ArrayList<>();
    private final Set<AssetOccurrence> occurrenceSet = new HashSet<>();
    private final Set<CryptoAsset> dependsOnSet = new HashSet<>();

    CryptoAsset(String name, CryptoAssetProperties properties) {
        this.name = Objects.requireNonNull(name, "name");
        this.properties = Objects.requireNonNull(properties, "properties");
    }

    /**
     * The asset's name.
     *
     * @return e.g. {@code AES-256-GCM}, {@code SHA-256} or {@code secret-key}
     */
    public String name() {
        return name;
    }

    /**
     * What the asset is.
     *
     * @return the properties of its asset type
     */
    public CryptoAssetProperties properties() {
        return properties;
    }

    /**
     * Where the asset occurs.
     *
     * @return the occurrences, in the order they were found; unmodifiable
     */
    public List<AssetOccurrence> occurrences() {
        return Collections.unmodifiableList(occurrences);
    }

    /**
     * The assets this one depends on, over all its occurrences.
     *
     * @return the assets, in the order they were linked; unmodifiable
     */
    public List<CryptoAsset> dependsOn() {
        return Collections.unmodifiableList(dependsOn);
    }

    /** Adds an occurrence unless the asset has it already. */
    void addOccurrence(AssetOccurrence occurrence) {
        if (occurrenceSet.add(occurrence)) {
            occurrences.add(occurrence);
        }
    }

    /** Replaces the occurrences with those a function makes of them, e.g. with their reachability. */
    void replaceOccurrences(UnaryOperator<AssetOccurrence> f) {
        for (int i = 0; i < occurrences.size(); i++) {
            occurrences.set(i, f.apply(occurrences.get(i)));
        }
    }

    /** Adds a dependency unless the asset has it already, or it is the asset itself. */
    void addDependency(CryptoAsset asset) {
        if (asset != this && dependsOnSet.add(asset)) {
            dependsOn.add(asset);
        }
    }

    /**
     * Assets are equal when their content is: name and properties.
     *
     * @param o the other object
     * @return whether it is an asset with the same name and properties
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof CryptoAsset a && name.equals(a.name) && properties.equals(a.properties);
    }

    @Override
    public int hashCode() {
        return 31 * name.hashCode() + properties.hashCode();
    }

    /**
     * Returns the asset's content.
     *
     * @return its name and properties
     */
    @Override
    public String toString() {
        return name + " " + properties;
    }
}
