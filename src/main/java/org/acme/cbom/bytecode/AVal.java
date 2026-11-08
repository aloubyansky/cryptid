package org.acme.cbom.bytecode;

import java.util.HashSet;
import java.util.Set;

/**
 * Abstract value of the bytecode interpreter: the constants a value may be, the enclosing method's
 * parameters it may be passed through from, and the objects it may refer to, identified by the call
 * site that created them ({@code new}, or a method returning an object). Values merge by union at
 * control flow joins.
 *
 * <p>The lattice is finite, so the data-flow analysis terminates: when a value may be more than
 * {@value #MAX_CONSTS} constants, it becomes {@code anyConst}, which absorbs all further constants.
 *
 * @param consts possible constant values: {@code String}, {@code Integer}, {@code Long}, ...; empty
 *     if {@code anyConst}
 * @param anyConst whether the value may be too many constants to track, i.e. no usable constant
 * @param params bit {@code p} set = the value may be the enclosing method's parameter {@code p},
 *     passed through unchanged (loads, stores, casts); values computed from a parameter don't
 *     carry it, since a caller's constant wouldn't be their value
 * @param origins ids of the call sites that may have created the object
 * @param wide whether the value takes two stack slots ({@code long}, {@code double})
 */
record AVal(Set<Object> consts, boolean anyConst, long params, Set<Integer> origins, boolean wide) {

    /** Constants beyond this count are not tracked. */
    static final int MAX_CONSTS = 16;

    /** Parameters beyond this index aren't tracked. */
    static final int MAX_PARAMS = 63;

    static final AVal UNKNOWN = new AVal(Set.of(), false, 0, Set.of(), false);
    static final AVal UNKNOWN_WIDE = new AVal(Set.of(), false, 0, Set.of(), true);

    static AVal unknown(int size) {
        return size == 2 ? UNKNOWN_WIDE : UNKNOWN;
    }

    static AVal constant(Object value, int size) {
        return new AVal(Set.of(value), false, 0, Set.of(), size == 2);
    }

    static AVal constants(Set<Object> values) {
        return new AVal(values, false, 0, Set.of(), false);
    }

    static AVal origin(int id) {
        return new AVal(Set.of(), false, 0, Set.of(id), false);
    }

    /**
     * The value of a method parameter on entry.
     *
     * @param index the parameter index, not the local variable slot
     * @param size the number of slots the parameter takes
     */
    static AVal param(int index, int size) {
        return new AVal(Set.of(), false, index < MAX_PARAMS ? 1L << index : 0, Set.of(), size == 2);
    }

    AVal withSize(int size) {
        return (size == 2) == wide ? this : new AVal(consts, anyConst, params, origins, size == 2);
    }

    /** The single constant value, or {@code null} if there are none or several. */
    Object single() {
        return consts.size() == 1 ? consts.iterator().next() : null;
    }

    /**
     * Merges two values.
     *
     * @param o the other value
     * @return {@code this} if merging adds nothing, otherwise the union
     */
    AVal merge(AVal o) {
        if (o == this) {
            return this;
        }
        final boolean any = anyConst || o.anyConst;
        final boolean sameConsts = any ? anyConst : consts.containsAll(o.consts);
        final boolean sameOrigins = origins.containsAll(o.origins);
        final boolean sameParams = (params | o.params) == params;
        if (sameConsts && sameOrigins && sameParams && (wide || !o.wide)) {
            return this;
        }
        Set<Object> c;
        boolean anyResult = any;
        if (any) {
            c = Set.of();
        } else {
            final Set<Object> u = new HashSet<>(consts);
            u.addAll(o.consts);
            if (u.size() > MAX_CONSTS) {
                c = Set.of();
                anyResult = true;
            } else {
                c = Set.copyOf(u);
            }
        }
        final Set<Integer> r;
        if (sameOrigins) {
            r = origins;
        } else {
            final Set<Integer> u = new HashSet<>(origins);
            u.addAll(o.origins);
            r = Set.copyOf(u);
        }
        return new AVal(c, anyResult, params | o.params, r, wide || o.wide);
    }
}
