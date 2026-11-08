package org.acme.cbom.bytecode;

/**
 * Location of a detection: the call site's source file, line and method signature. Used as the
 * tree type {@code T} of sonar-cryptography's generic rule and value model.
 *
 * @param file the source file path
 * @param line the line number, from the {@code LineNumberTable}
 * @param signature the called method in sonar-java's format
 * @param methodName the called method's name
 */
record Loc(String file, int line, String signature, String methodName)
        implements org.sonar.plugins.java.api.tree.Tree {

    static Loc of(CallSite cs) {
        return new Loc(cs.sourceFile, cs.line, cs.signature(), cs.name);
    }
}
