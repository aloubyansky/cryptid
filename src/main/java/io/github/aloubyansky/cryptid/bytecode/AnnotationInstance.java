package io.github.aloubyansky.cryptid.bytecode;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An annotation on a class, method or parameter, with its constant element values.
 *
 * @param type the annotation type's binary name, e.g. {@code jakarta.ws.rs.GET}
 * @param values element values by name: {@code String}s, boxed primitives, enum constants as
 *     {@code Type.CONSTANT}, classes as binary names, and arrays as lists of these; nested
 *     annotations are left out
 */
public record AnnotationInstance(String type, Map<String, Object> values) {

    /** Copies the values. */
    public AnnotationInstance {
        values = Map.copyOf(values);
    }

    /**
     * Returns an element's value as strings: a single value, or an array's values.
     *
     * @param element the element's name, e.g. {@code value}
     * @return the values; empty if the element isn't given
     */
    public List<String> strings(String element) {
        final Object v = values.get(element);
        if (v == null) {
            return List.of();
        }
        if (v instanceof List<?> l) {
            return l.stream().map(String::valueOf).toList();
        }
        return List.of(String.valueOf(v));
    }

    /**
     * Returns the first value of an element, as a string.
     *
     * @param element the element's name
     * @return the value, or empty if the element isn't given or is an empty array
     */
    public Optional<String> string(String element) {
        final List<String> all = strings(element);
        return all.isEmpty() ? Optional.empty() : Optional.of(all.get(0));
    }

    /**
     * Returns the annotation type's simple name.
     *
     * @return e.g. {@code GET}
     */
    public String simpleName() {
        final int i = Math.max(type.lastIndexOf('.'), type.lastIndexOf('$'));
        return type.substring(i + 1);
    }
}
