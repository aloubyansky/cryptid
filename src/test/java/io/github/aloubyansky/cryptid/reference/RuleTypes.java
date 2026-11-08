package io.github.aloubyansky.cryptid.reference;

import com.ibm.engine.detection.IType;
import io.github.aloubyansky.cryptid.bytecode.Types;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.util.ArrayList;
import java.util.List;

/**
 * sonar-cryptography's {@link IType} predicates over the class hierarchy of {@link Types}, which
 * its {@code MethodMatcher} evaluates. Only the rule-based reference uses them.
 */
public final class RuleTypes {

    private RuleTypes() {}

    /**
     * Returns a type predicate for a class: matching itself and, unless exact, its supertypes.
     *
     * @param types the class hierarchy
     * @param internalName the class
     * @param exact whether to match the class only
     * @return the predicate
     */
    public static IType ofClass(Types types, String internalName, boolean exact) {
        final String fqn = internalName.replace('/', '.');
        return typeString -> typeString.equals(fqn) || !exact && types.supertypeNames(internalName).contains(typeString);
    }

    /**
     * Returns type predicates for the parameters of a method descriptor.
     *
     * @param types the class hierarchy
     * @param descriptor the descriptor
     * @return the predicates, by parameter position
     */
    public static List<IType> ofParameters(Types types, String descriptor) {
        final List<IType> result = new ArrayList<>();
        for (ClassDesc p : MethodTypeDesc.ofDescriptor(descriptor).parameterList()) {
            result.add(of(types, p));
        }
        return List.copyOf(result);
    }

    private static IType of(Types types, ClassDesc d) {
        if (d.isPrimitive() || d.isArray()) {
            final String name = sonarName(d);
            return name::equals;
        }
        final String desc = d.descriptorString();
        return ofClass(types, desc.substring(1, desc.length() - 1), false);
    }

    /** Type names as sonar-java prints them, e.g. {@code int}, {@code byte[]}. */
    private static String sonarName(ClassDesc d) {
        if (d.isArray()) {
            return sonarName(d.componentType()) + "[]";
        }
        if (d.isPrimitive()) {
            return d.displayName();
        }
        final String desc = d.descriptorString();
        return desc.substring(1, desc.length() - 1).replace('/', '.');
    }
}
