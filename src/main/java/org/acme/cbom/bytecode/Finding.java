package org.acme.cbom.bytecode;

import com.ibm.engine.detection.DetectionStore;

/**
 * A detection to translate and report on its own.
 *
 * @param loc where to report it: the matched call, or for a value resolved from a caller, the
 *     caller's call site
 * @param call the matched call
 * @param store its store tree, the input of sonar-cryptography's translation
 */
record Finding(Loc loc, CallSite call, DetectionStore<Object, Loc, Object, Object> store) {}
