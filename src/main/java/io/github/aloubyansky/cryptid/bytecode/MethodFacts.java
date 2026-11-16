package io.github.aloubyansky.cryptid.bytecode;

import java.util.List;

/**
 * What a method does that the call graph needs, read from its instructions without interpreting
 * them.
 *
 * @param method the method, {@code owner.name+descriptor} with the internal class name
 * @param calls the methods it calls and the targets of the method handles it creates, distinct, in
 *     the order they first occur
 * @param instantiated internal names of the classes it creates instances of, with {@code new} or
 *     through a constructor reference; distinct
 */
public record MethodFacts(String method, List<Call> calls, List<String> instantiated) {

    /** How a call selects the method to run. */
    public enum Kind {
        /** {@code invokestatic}. */
        STATIC,
        /** {@code invokespecial}: constructors, private methods and {@code super} calls. */
        SPECIAL,
        /** {@code invokevirtual}. */
        VIRTUAL,
        /** {@code invokeinterface}. */
        INTERFACE
    }

    /**
     * A called method.
     *
     * @param kind how the method to run is selected
     * @param owner the internal name of the class the call names
     * @param name the method's name, {@code <init>} for a constructor
     * @param descriptor the method's descriptor
     * @param handle whether this is the target of a method handle the method creates (a lambda's
     *     body, a method reference), not a call it makes itself
     */
    public record Call(Kind kind, String owner, String name, String descriptor, boolean handle) {}
}
