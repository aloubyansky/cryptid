package io.github.aloubyansky.cryptid.bytecode;

import java.util.List;
import java.util.Set;

/**
 * A class's supertypes and declared methods, as the class table holds it.
 *
 * @param superclass internal name of the superclass, {@code null} for {@code java.lang.Object}
 * @param interfaces internal names of the directly implemented interfaces
 * @param methods declared methods as {@code name + descriptor}
 */
public record ClassInfo(String superclass, List<String> interfaces, Set<String> methods) {}
