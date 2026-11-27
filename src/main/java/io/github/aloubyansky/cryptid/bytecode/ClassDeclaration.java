package io.github.aloubyansky.cryptid.bytecode;

import java.util.List;

/**
 * A class as a class file declares it, as far as entry points and instantiation need: its
 * annotations and its methods.
 *
 * @param className the internal name
 * @param flags the access flags
 * @param annotations the class's annotations
 * @param methods its declared methods; only those with an annotation of interest, unless all were
 *     asked for
 */
public record ClassDeclaration(String className, int flags, List<AnnotationInstance> annotations, List<MethodDeclaration> methods) {

    /** Copies the lists. */
    public ClassDeclaration {
        annotations = List.copyOf(annotations);
        methods = List.copyOf(methods);
    }
}
