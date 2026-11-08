package io.github.aloubyansky.cryptid.detection;

import io.github.aloubyansky.cryptid.bytecode.CallSite;

/**
 * A detection to translate and report on its own.
 *
 * @param loc where to report it: the matched call, or for a value resolved from a caller, the
 *     caller's call site
 * @param call the matched call
 * @param event its event tree
 */
public record Finding(Loc loc, CallSite call, CryptoEvent event) {}
