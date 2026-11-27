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

    /** What the code at an occurrence does with the asset. */
    public enum Role {
        /**
         * The code uses the asset through an API: obtains an algorithm, key or protocol and
         * performs or sets up an operation with it. Code that only names an algorithm, e.g. in a
         * table of supported ones, counts as a use too.
         */
        USE,
        /**
         * The code implements the asset, or makes it available to others: it is in a class
         * implementing crypto, e.g. a JCA provider's, or it calls an API of its own artifact,
         * e.g. a library composing its own primitives.
         */
        PROVISION
    }

    /**
     * Whether an occurrence is reached, from which entry points, and by which path.
     *
     * @param reachability the reachability
     * @param reachedBy the entry points reaching the occurrence's method; empty if not reached, or
     *     if it is reached only by the runtime, e.g. a bean's constructor
     * @param path a shortest call path to the occurrence's method, the entry point's method first;
     *     empty if not reached
     */
    public record Reach(Reachability reachability, List<EntryPoint> reachedBy, List<MethodId> path) {

        /** Unknown reachability. */
        public static final Reach UNKNOWN = new Reach(Reachability.UNKNOWN, List.of(), List.of());

        /** Not reached. */
        public static final Reach NOT_REACHED = new Reach(Reachability.NOT_REACHED, List.of(), List.of());

        /** Copies the lists. */
        public Reach {
            Objects.requireNonNull(reachability, "reachability");
            reachedBy = List.copyOf(reachedBy);
            path = List.copyOf(path);
        }
    }

    private final CodeLocation location;
    private final Role role;
    private final Reach reach;

    AssetOccurrence(CodeLocation location, Role role) {
        this(location, role, Reach.UNKNOWN);
    }

    AssetOccurrence(CodeLocation location, Role role, Reach reach) {
        this.location = Objects.requireNonNull(location, "location");
        this.role = Objects.requireNonNull(role, "role");
        this.reach = Objects.requireNonNull(reach, "reach");
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
     * What the code at the occurrence does with the asset.
     *
     * @return a use or a provision
     */
    public Role role() {
        return role;
    }

    /**
     * Whether the application reaches the occurrence.
     *
     * @return {@link Reachability#UNKNOWN} until reachability is computed
     */
    public Reachability reachability() {
        return reach.reachability();
    }

    /**
     * The entry points the occurrence is reached from.
     *
     * @return the entry points, in the inventory's order; empty unless {@link
     *     Reachability#REACHED}, and empty for an occurrence reached only by the runtime, e.g. in a
     *     bean's constructor
     */
    public List<EntryPoint> reachedBy() {
        return reach.reachedBy();
    }

    /**
     * A shortest call path from an entry point to the occurrence's method.
     *
     * @return the methods, the entry point's first and the occurrence's last; empty unless
     *     {@link Reachability#REACHED}
     */
    public List<MethodId> path() {
        return reach.path();
    }

    /** This occurrence with a reachability. */
    AssetOccurrence withReach(Reach r) {
        return new AssetOccurrence(location, role, r);
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
        return "AssetOccurrence[location=" + location + ", role=" + role + ", reachability=" + reach.reachability() + "]";
    }
}
