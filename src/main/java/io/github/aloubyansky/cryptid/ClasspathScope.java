package io.github.aloubyansky.cryptid;

/** Which JARs an artifact's classes' supertypes are resolved from, for specs matching subtypes. */
public enum ClasspathScope {
    /**
     * The artifact's dependencies, transitively; all analyzed JARs for an artifact whose
     * dependencies aren't known.
     */
    DEPENDENCIES,
    /** All analyzed JARs. */
    ALL,
    /** The artifact's JAR only, and the JDK. */
    NONE
}
