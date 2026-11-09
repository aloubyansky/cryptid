package io.github.aloubyansky.cryptid.spec;

import io.github.aloubyansky.cryptid.bytecode.CallSite;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The crypto API specs indexed for matching call sites, the way sonar-cryptography's {@code
 * MethodMatcher} matches: by method name, then the owner (the call's owner for exact specs, or one
 * of its supertypes), then the parameters. A class-typed parameter matches when the spec's type is
 * the call's parameter type or one of its supertypes, since an API may have narrowed a parameter
 * since the spec was written, e.g. Bouncy Castle's {@code ShortenedDigest(ExtendedDigest, int)}
 * for a spec of {@code (Digest, int)}. Primitive and array parameters must be equal. A spec with
 * {@link CryptoApiSpecs#ANY_PARAMETERS} accepts any parameters.
 *
 * <p>Immutable and thread-safe once built.
 */
public final class CryptoApiMatcher {

    /**
     * A spec split for matching.
     *
     * @param owner the owner type
     * @param parameters the parameter types, or {@code null} for any
     * @param spec the spec
     */
    private record Entry(String owner, List<String> parameters, ApiSpec spec) {}

    /** {@code name/parameter count}, or {@code name/...} for any parameters -> specs, in api order. */
    private final Map<String, List<Entry>> byMethod = new HashMap<>();
    private final Map<String, Map<String, String>> names;

    /**
     * Indexes specs.
     *
     * @param specs the specs
     * @throws IllegalArgumentException if a value names a table the specs don't have
     */
    public CryptoApiMatcher(CryptoApiSpecs specs) {
        this.names = specs.names();
        for (ApiSpec spec : specs.apis()) {
            for (CryptoApiSpecs.Arg arg : spec.args()) {
                if (arg.value() != null && arg.value().names() != null && !names.containsKey(arg.value().names())) {
                    throw new IllegalArgumentException(spec.api() + " names the missing table " + arg.value().names());
                }
            }
            final String api = spec.api();
            final int hash = api.indexOf('#');
            final int paren = api.indexOf('(', hash);
            final String name = api.substring(hash + 1, paren);
            final String params = api.substring(paren + 1, api.length() - 1);
            final List<String> types = params.equals(CryptoApiSpecs.ANY_PARAMETERS) ? null
                    : params.isEmpty() ? List.of() : List.of(params.split(", "));
            byMethod.computeIfAbsent(name + "/" + (types == null ? CryptoApiSpecs.ANY_PARAMETERS : types.size()), k -> new ArrayList<>())
                    .add(new Entry(api.substring(0, hash), types, spec));
        }
    }

    /**
     * Translates a constant with a value's name table.
     *
     * @param value the value's factory spec
     * @param constant the argument's constant
     * @return the constant, translated if the value names a table, or {@code null} if it isn't in
     *     the table
     */
    public Object name(CryptoApiSpecs.Factory value, Object constant) {
        return value.names() == null ? constant : names.get(value.names()).get(String.valueOf(constant));
    }

    /**
     * Returns the specs a call matches.
     *
     * @param cs the call site
     * @param types the class hierarchy
     * @return the matching specs, in {@link ApiSpec#api()} order; empty if none
     */
    public List<ApiSpec> match(CallSite cs, Types types) {
        final List<ClassDesc> params = MethodTypeDesc.ofDescriptor(cs.descriptor()).parameterList();
        final List<Entry> exact = byMethod.getOrDefault(cs.name() + "/" + params.size(), List.of());
        final List<Entry> any = byMethod.getOrDefault(cs.name() + "/" + CryptoApiSpecs.ANY_PARAMETERS, List.of());
        if (exact.isEmpty() && any.isEmpty()) {
            return List.of();
        }
        final List<Entry> entries;
        if (any.isEmpty()) {
            entries = exact;
        } else {
            entries = new ArrayList<>(exact);
            entries.addAll(any);
            entries.sort(Comparator.comparing(e -> e.spec().api()));
        }
        final String owner = cs.owner().replace('/', '.');
        Set<String> supertypes = null;
        final List<ApiSpec> result = new ArrayList<>(1);
        for (Entry e : entries) {
            final boolean ownerMatches;
            if (e.spec().subtypes()) {
                if (supertypes == null) {
                    supertypes = types.supertypeNames(cs.owner());
                }
                ownerMatches = supertypes.contains(e.owner());
            } else {
                ownerMatches = e.owner().equals(owner);
            }
            if (ownerMatches && parametersMatch(e.parameters(), params, types)) {
                result.add(e.spec());
            }
        }
        return result;
    }

    private static boolean parametersMatch(List<String> expected, List<ClassDesc> actual, Types types) {
        if (expected == null) {
            return true;
        }
        for (int i = 0; i < expected.size(); i++) {
            final ClassDesc d = actual.get(i);
            final String name = typeName(d);
            if (name.equals(expected.get(i))) {
                continue;
            }
            if (d.isPrimitive() || d.isArray() || !types.supertypeNames(name.replace('.', '/')).contains(expected.get(i))) {
                return false;
            }
        }
        return true;
    }

    /** Parameter types of a method descriptor as in the specs, e.g. {@code int, byte[], java.lang.String}. */
    static String parameters(String descriptor) {
        final StringBuilder sb = new StringBuilder();
        for (ClassDesc p : MethodTypeDesc.ofDescriptor(descriptor).parameterList()) {
            if (!sb.isEmpty()) {
                sb.append(", ");
            }
            sb.append(typeName(p));
        }
        return sb.toString();
    }

    private static String typeName(ClassDesc d) {
        if (d.isArray()) {
            return typeName(d.componentType()) + "[]";
        }
        if (d.isPrimitive()) {
            return d.displayName();
        }
        final String desc = d.descriptorString();
        return desc.substring(1, desc.length() - 1).replace('/', '.');
    }
}
