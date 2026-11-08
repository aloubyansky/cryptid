package org.acme.cbom.bytecode;

import java.lang.reflect.Constructor;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.acme.cbom.spec.ApiSpecs.Factory;

/**
 * Creates sonar-cryptography's value and action factories from their description in the specs:
 * the class name in {@code com.ibm.engine.model.factory} and at most one configuration value,
 * passed to the constructor taking it (a {@code String} or an enum constant).
 *
 * <p>Rule-specific functions ({@code factory: lambda}) can't be created this way; {@link #create}
 * returns {@code null} for them. Thread-safe; factories are cached.
 */
final class SpecFactories {

    private static final String PACKAGE = "com.ibm.engine.model.factory.";
    private static final Map<Factory, Object> CACHE = new ConcurrentHashMap<>();

    private SpecFactories() {}

    /**
     * Returns the factory a spec describes.
     *
     * @param spec the description
     * @return an {@code IValueFactory} or {@code IActionFactory}, or {@code null} for a
     *     rule-specific function
     * @throws IllegalArgumentException if the factory can't be created
     */
    static Object create(Factory spec) {
        if ("lambda".equals(spec.factory())) {
            return null;
        }
        return CACHE.computeIfAbsent(spec, SpecFactories::instantiate);
    }

    /**
     * Creates the action a rule-specific function produced when exported, from its recorded result
     * ({@code <value class> <value>}, e.g. {@code Mode GCM}): the value class in {@code
     * com.ibm.engine.model} constructed with the value and the location.
     *
     * @param spec the description, with {@code factory: lambda}
     * @param location the call's location
     * @return the action
     * @throws IllegalArgumentException if it can't be created
     */
    static Object lambdaAction(Factory spec, Loc location) {
        final String result = spec.result();
        final int space = result == null ? -1 : result.indexOf(' ');
        if (space < 0) {
            throw new IllegalArgumentException("No result recorded: " + spec);
        }
        try {
            return Class.forName("com.ibm.engine.model." + result.substring(0, space))
                    .getConstructor(String.class, Object.class)
                    .newInstance(result.substring(space + 1), location);
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Can't create " + result, e);
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object instantiate(Factory spec) {
        try {
            final Class<?> type = Class.forName(PACKAGE + spec.factory());
            if (spec.config().isEmpty()) {
                return type.getConstructor().newInstance();
            }
            if (spec.config().size() > 1) {
                throw new IllegalArgumentException("More than one configuration value: " + spec);
            }
            final String value = spec.config().values().iterator().next();
            for (Constructor<?> c : type.getConstructors()) {
                if (c.getParameterCount() != 1) {
                    continue;
                }
                final Class<?> p = c.getParameterTypes()[0];
                if (p == String.class) {
                    return c.newInstance(value);
                }
                if (p.isEnum()) {
                    return c.newInstance(Enum.valueOf((Class<? extends Enum>) p, value));
                }
            }
            throw new IllegalArgumentException("No constructor taking the configuration: " + spec);
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Can't create " + spec, e);
        }
    }
}
