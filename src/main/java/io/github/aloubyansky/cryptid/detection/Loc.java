package io.github.aloubyansky.cryptid.detection;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.bytecode.CallSite;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Location of a detection: the call site's source file, line and method signature. Used as the
 * tree type {@code T} of sonar-cryptography's generic rule and value model.
 *
 * <p>It implements the {@code Tree} marker only for the tests that still run sonar-cryptography's
 * rules as a reference: two of them are lambdas typed on sonar-java's {@code Tree}.
 *
 * @param file the source file path
 * @param line the line number, from the {@code LineNumberTable}
 * @param signature the called method in sonar-java's format
 * @param methodName the called method's name
 * @param code the call in the result model, or {@code null} where there is none, e.g. in tests
 */
public record Loc(String file, int line, String signature, String methodName, CodeLocation code) implements Tree {

    /**
     * A location without a code location, e.g. for probing factories.
     *
     * @param file the source file path
     * @param line the line number
     * @param signature the called method in sonar-java's format
     * @param methodName the called method's name
     */
    public Loc(String file, int line, String signature, String methodName) {
        this(file, line, signature, methodName, null);
    }

    /**
     * The location of a call site, without a code location.
     *
     * @param cs the call site
     * @return its source file, line and called method
     */
    public static Loc of(CallSite cs) {
        return of(cs, null);
    }

    /**
     * The location of a call site in an artifact.
     *
     * @param cs the call site
     * @param artifact the artifact containing it, or {@code null} for no code location
     * @return its source file, line and called method, with its code location
     */
    public static Loc of(CallSite cs, ArtifactCoordinates artifact) {
        return new Loc(cs.sourceFile(), cs.line(), cs.signature(), cs.name(),
                artifact == null ? null : CodeLocations.of(artifact, cs));
    }
}
