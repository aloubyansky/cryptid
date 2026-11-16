package io.github.aloubyansky.cryptid.bytecode;

import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Call;
import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Kind;
import io.smallrye.classfile.CodeElement;
import io.smallrye.classfile.MethodModel;
import io.smallrye.classfile.instruction.ConstantInstruction;
import io.smallrye.classfile.instruction.InvokeDynamicInstruction;
import io.smallrye.classfile.instruction.InvokeInstruction;
import io.smallrye.classfile.instruction.NewObjectInstruction;
import java.lang.constant.ConstantDesc;
import java.lang.constant.DirectMethodHandleDesc;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Reads a method's {@link MethodFacts} from its instructions. */
final class GraphFacts {

    private GraphFacts() {}

    /**
     * Reads the facts of a method.
     *
     * @param className the internal name of the method's class
     * @param mm the method
     * @return its facts; empty lists for a method without code
     */
    static MethodFacts of(String className, MethodModel mm) {
        final String method = className + "." + mm.methodName().stringValue() + mm.methodType().stringValue();
        if (mm.code().isEmpty()) {
            return new MethodFacts(method, List.of(), List.of());
        }
        final Set<Call> calls = new LinkedHashSet<>();
        final Set<String> instantiated = new LinkedHashSet<>();
        for (CodeElement el : mm.code().get()) {
            if (el instanceof InvokeInstruction ii) {
                final Kind kind = switch (ii.opcode()) {
                    case INVOKESTATIC -> Kind.STATIC;
                    case INVOKESPECIAL -> Kind.SPECIAL;
                    case INVOKEINTERFACE -> Kind.INTERFACE;
                    default -> Kind.VIRTUAL;
                };
                calls.add(new Call(kind, ii.owner().asInternalName(), ii.name().stringValue(), ii.type().stringValue(), false));
            } else if (el instanceof NewObjectInstruction n) {
                instantiated.add(n.className().asInternalName());
            } else if (el instanceof InvokeDynamicInstruction id) {
                for (ConstantDesc arg : id.bootstrapArgs()) {
                    handle(arg, calls, instantiated);
                }
            } else if (el instanceof ConstantInstruction ci) {
                handle(ci.constantValue(), calls, instantiated);
            }
        }
        return new MethodFacts(method, List.copyOf(calls), List.copyOf(instantiated));
    }

    /** Adds the method a handle refers to; handles of fields refer to none. */
    private static void handle(ConstantDesc constant, Set<Call> calls, Set<String> instantiated) {
        if (!(constant instanceof DirectMethodHandleDesc h)) {
            return;
        }
        final Kind kind;
        switch (h.kind()) {
            case STATIC, INTERFACE_STATIC -> kind = Kind.STATIC;
            case VIRTUAL -> kind = Kind.VIRTUAL;
            case INTERFACE_VIRTUAL -> kind = Kind.INTERFACE;
            case SPECIAL, INTERFACE_SPECIAL, CONSTRUCTOR -> kind = Kind.SPECIAL;
            default -> {
                return;
            }
        }
        final String owner = internalName(h);
        final boolean constructor = h.kind() == DirectMethodHandleDesc.Kind.CONSTRUCTOR;
        calls.add(new Call(kind, owner, constructor ? "<init>" : h.methodName(), h.lookupDescriptor(), true));
        if (constructor) {
            instantiated.add(owner);
        }
    }

    /** The internal name of a handle's owner. */
    static String internalName(DirectMethodHandleDesc h) {
        final String d = h.owner().descriptorString();
        return d.startsWith("L") ? d.substring(1, d.length() - 1) : d;
    }
}
