package io.github.aloubyansky.cryptid.detection;

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
 */
public record Loc(String file, int line, String signature, String methodName) implements Tree {

    /**
     * The location of a call site.
     *
     * @param cs the call site
     * @return its source file, line and called method
     */
    public static Loc of(CallSite cs) {
        return new Loc(cs.sourceFile(), cs.line(), cs.signature(), cs.name());
    }
}
