package io.github.aloubyansky.cryptid.detection;

import io.github.aloubyansky.cryptid.bytecode.CallSite;

/**
 * A detection to translate and report on its own.
 *
 * @param loc where to report it: the matched call, or for a value resolved from a caller, the
 *     caller's call site
 * @param call the matched call
 * @param event its event tree
 * @param variant whether it is one of several findings of the call, one per combination of the
 *     values its arguments may have, or a value resolved from a caller, one of those its callers
 *     pass; such a value may be one the API rejects at runtime
 */
public record Finding(Loc loc, CallSite call, CryptoEvent event, boolean variant) {}
