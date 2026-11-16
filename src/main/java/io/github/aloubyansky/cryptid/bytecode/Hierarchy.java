package io.github.aloubyansky.cryptid.bytecode;

import io.github.aloubyansky.cryptid.bytecode.CallIndex.ClassInfo;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The analyzed classes of all artifacts, with their supertypes and declared methods, for resolving
 * a called method to the class declaring it. Thread-safe.
 */
public final class Hierarchy {

    private final Map<String, ClassInfo> classes = new ConcurrentHashMap<>();
    private final Map<String, List<String>> supertypes = new ConcurrentHashMap<>();

    /**
     * Records the classes of an artifact. Of a class in several artifacts, the first one recorded
     * is kept.
     *
     * @param infos class infos by internal name
     */
    public void add(Map<String, ClassInfo> infos) {
        infos.forEach(classes::putIfAbsent);
    }

    /**
     * Returns an analyzed class.
     *
     * @param internalName the class's internal name
     * @return its info, or {@code null} if the class isn't analyzed
     */
    public ClassInfo get(String internalName) {
        return classes.get(internalName);
    }

    /** The analyzed classes by internal name; a live view. */
    Map<String, ClassInfo> classes() {
        return classes;
    }

    /**
     * Resolves a method to the class declaring it: along the superclass chain, as the JVM
     * resolves methods, then the interfaces, for default methods.
     *
     * @param methodKey {@code owner.name+descriptor}
     * @return the key with the declaring class as owner, or the key itself if no analyzed class
     *     declares the method
     */
    public String declaring(String methodKey) {
        final int dot = methodKey.indexOf('.');
        final String owner = methodKey.substring(0, dot);
        final String member = methodKey.substring(dot + 1);
        for (String c = owner; c != null; ) {
            final ClassInfo ci = classes.get(c);
            if (ci == null) {
                break;
            }
            if (ci.methods().contains(member)) {
                return c + "." + member;
            }
            c = ci.superclass();
        }
        for (String t : supertypes(owner)) {
            final ClassInfo ci = classes.get(t);
            if (ci != null && ci.methods().contains(member)) {
                return t + "." + member;
            }
        }
        return methodKey;
    }

    /**
     * Returns the analyzed supertypes of a class, superclasses and interfaces, transitively,
     * nearest first. Call it only once all classes are recorded: results are cached.
     *
     * @param internalName the class's internal name
     * @return the supertypes, without the class itself
     */
    public List<String> supertypes(String internalName) {
        return supertypes.computeIfAbsent(internalName, o -> {
            final List<String> result = new ArrayList<>();
            final Set<String> seen = new HashSet<>(Set.of(o));
            final Deque<String> todo = new ArrayDeque<>(List.of(o));
            while (!todo.isEmpty()) {
                final ClassInfo ci = classes.get(todo.poll());
                if (ci == null) {
                    continue;
                }
                final List<String> next = new ArrayList<>();
                if (ci.superclass() != null) {
                    next.add(ci.superclass());
                }
                next.addAll(ci.interfaces());
                for (String n : next) {
                    if (seen.add(n)) {
                        result.add(n);
                        todo.add(n);
                    }
                }
            }
            return List.copyOf(result);
        });
    }
}
