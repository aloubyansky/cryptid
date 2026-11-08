package io.github.aloubyansky.cryptid.detection;

import java.util.HashMap;
import java.util.Map;

/**
 * Classes looked up by simple name, from explicit lists. The specs name sonar-cryptography's
 * factory and context classes by simple name; listing them as class literals keeps them in the
 * tree-shaken runner JAR, which a lookup by name alone wouldn't.
 */
final class KnownClasses {

    private KnownClasses() {}

    /**
     * Indexes classes by simple name.
     *
     * @param classes the classes
     * @return the classes by simple name
     */
    static Map<String, Class<?>> bySimpleName(Class<?>... classes) {
        final Map<String, Class<?>> result = new HashMap<>();
        for (Class<?> c : classes) {
            result.put(c.getSimpleName(), c);
        }
        return Map.copyOf(result);
    }

    /**
     * Returns the class of a simple name.
     *
     * @param classes the classes by simple name
     * @param name the simple name
     * @return the class
     * @throws ClassNotFoundException if no class of that name is listed
     */
    static Class<?> get(Map<String, Class<?>> classes, String name) throws ClassNotFoundException {
        final Class<?> c = classes.get(name);
        if (c == null) {
            throw new ClassNotFoundException(name);
        }
        return c;
    }
}
