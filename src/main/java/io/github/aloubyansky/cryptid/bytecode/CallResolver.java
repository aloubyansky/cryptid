package io.github.aloubyansky.cryptid.bytecode;

import java.util.List;

/** Resolves the values of a method's parameters from its callers, possibly in other artifacts. */
public interface CallResolver {

    /**
     * Resolves the values of a method's parameters from its callers: the constants they pass,
     * and, where a caller passes on its own parameter or a field stored from one, those its
     * callers pass, up to a limit of calls away.
     *
     * @param method the method, {@code owner.name+descriptor}
     * @param params the parameters to resolve, one bit per parameter index
     * @return the constants passed by callers, each with the call site passing it, in a stable
     *     order; empty if none
     */
    List<CallIndex.Hit> resolve(String method, long params);
}
