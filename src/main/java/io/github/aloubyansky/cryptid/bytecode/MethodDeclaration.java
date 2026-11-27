package io.github.aloubyansky.cryptid.bytecode;

import java.lang.reflect.Modifier;
import java.util.List;

/**
 * A method as a class file declares it: its member key, access flags and annotations.
 *
 * @param member {@code name+descriptor}
 * @param flags the access flags, as {@link Modifier} has them, with {@code 0x1000} for synthetic
 *     and {@code 0x40} for bridge methods
 * @param annotations the method's annotations
 * @param parameters each parameter's annotations
 */
public record MethodDeclaration(String member, int flags, List<AnnotationInstance> annotations,
        List<List<AnnotationInstance>> parameters) {

    private static final int SYNTHETIC = 0x1000;
    private static final int BRIDGE = 0x40;

    /** Copies the lists. */
    public MethodDeclaration {
        annotations = List.copyOf(annotations);
        parameters = parameters.stream().map(List::copyOf).toList();
    }

    /**
     * The method's name.
     *
     * @return the name, {@code <init>} for a constructor
     */
    public String name() {
        return member.substring(0, member.indexOf('('));
    }

    /**
     * The method's descriptor.
     *
     * @return e.g. {@code ([Ljava/lang/String;)V}
     */
    public String descriptor() {
        return member.substring(member.indexOf('('));
    }

    /**
     * Whether the method is written in source: not synthetic, not a bridge, not a constructor or
     * initializer.
     *
     * @return {@code true} for a regular method
     */
    public boolean isRegular() {
        return (flags & (SYNTHETIC | BRIDGE)) == 0 && !member.startsWith("<");
    }

    /**
     * Whether the method is public.
     *
     * @return {@code true} if public
     */
    public boolean isPublic() {
        return Modifier.isPublic(flags);
    }

    /**
     * Whether the method is static.
     *
     * @return {@code true} if static
     */
    public boolean isStatic() {
        return Modifier.isStatic(flags);
    }

    /**
     * Whether the method has no code.
     *
     * @return {@code true} if abstract or native
     */
    public boolean isAbstract() {
        return Modifier.isAbstract(flags) || Modifier.isNative(flags);
    }
}
