package org.acme.cbom;

/**
 * Versions known at build time, filled in by the templating-maven-plugin from the pom, since the
 * uber-jar's merged manifest doesn't carry the versions of its dependencies.
 */
public final class BuildInfo {

    /** This tool's version. */
    public static final String VERSION = "${project.version}";

    /** The version of sonar-cryptography whose rules and CBOM model are used. */
    public static final String SONAR_CRYPTOGRAPHY_VERSION = "${sonar-cryptography.version}";

    private BuildInfo() {}
}
