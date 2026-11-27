package io.github.aloubyansky.cryptid;

/**
 * Where in the code a crypto asset occurs: a call in a method of an artifact. For an asset whose
 * value a caller passes in, e.g. an algorithm name given to a factory method, it is the caller's
 * call.
 *
 * @param artifact the artifact containing the method
 * @param sourceFile the source file of the method's class, from its {@code SourceFile} attribute,
 *     with its package directories, e.g. {@code org/acme/Foo.java}
 * @param method the method containing the call
 * @param line the call's line, {@code 0} if the class has no line number table
 * @param invokedMethod the called method
 */
public record CodeLocation(ArtifactCoordinates artifact, String sourceFile, MethodId method, int line, MethodId invokedMethod) {}
