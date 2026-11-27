package io.github.aloubyansky.cryptid;

import java.util.List;
import java.util.Objects;

/**
 * One place a crypto asset occurs. An occurrence is identified by its location: what is known
 * about it, such as whether the application reaches it, is attached to it and isn't part of its
 * identity.
 */
public final class AssetOccurrence {

    /** Whether an occurrence is reached from the application's entry points. */
    public enum Reachability {
        /** A path from an entry point leads to the occurrence's method. */
        REACHED,
        /** No path from the entry points searched for was found. */
        NOT_REACHED,
        /** Reachability wasn't computed, e.g. no entry points were found or searched for. */
        UNKNOWN
    }

    private final CodeLocation location;
    private final Reachability reachability;
    private final List<EntryPoint> reachedBy;

    AssetOccurrence(CodeLocation location) {
        this(location, Reachability.UNKNOWN, List.of());
    }

    AssetOccurrence(CodeLocation location, Reachability reachability, List<EntryPoint> reachedBy) {
        this.location = Objects.requireNonNull(location, "location");
        this.reachability = Objects.requireNonNull(reachability, "reachability");
        this.reachedBy = List.copyOf(reachedBy);
    }

    /**
     * Where in the code the asset occurs.
     *
     * @return the location
     */
    public CodeLocation location() {
        return location;
    }

    /**
     * Whether the application reaches the occurrence.
     *
     * @return {@link Reachability#UNKNOWN} until reachability is computed
     */
    public Reachability reachability() {
        return reachability;
    }

    /**
     * The entry points the occurrence is reached from.
     *
     * @return the entry points; empty unless {@link Reachability#REACHED}
     */
    public List<EntryPoint> reachedBy() {
        return reachedBy;
    }

    /**
     * Occurrences are equal when their locations are.
     *
     * @param o the other object
     * @return whether it is an occurrence at the same location
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof AssetOccurrence other && location.equals(other.location);
    }

    @Override
    public int hashCode() {
        return location.hashCode();
    }

    @Override
    public String toString() {
        return "AssetOccurrence[location=" + location + ", reachability=" + reachability + "]";
    }
}
