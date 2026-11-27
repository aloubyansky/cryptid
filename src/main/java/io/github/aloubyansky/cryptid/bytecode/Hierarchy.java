package io.github.aloubyansky.cryptid.bytecode;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * The analyzed classes of all artifacts, with their supertypes and declared methods: the class
 * table that spec matching and dispatch share. Thread-safe.
 *
 * <p>A class can be in several artifacts, e.g. shaded or of different versions. All copies are
 * kept. The hierarchy itself resolves a class to the copy of the first artifact in its order,
 * which the call index and the call graph use; a {@link View} resolves it from one artifact's
 * point of view, preferring the copies of the artifacts it lists, which spec matching uses.
 * Copies with the same info are one.
 */
public final class Hierarchy {

    /** A class's info with the artifact it was taken from. */
    private record Entry(String artifact, ClassInfo info) {}

    /** artifact path -> its position in the order, for artifacts given in the constructor */
    private final Map<String, Integer> order;
    /** internal name -> the copy resolved by default */
    private final Map<String, Entry> classes = new ConcurrentHashMap<>();
    /** internal name -> all copies, for classes in several artifacts */
    private final Map<String, List<Entry>> copies = new ConcurrentHashMap<>();
    private final Map<String, List<String>> supertypes = new ConcurrentHashMap<>();

    /** Creates a hierarchy whose artifacts are ordered by their paths. */
    public Hierarchy() {
        this(List.of());
    }

    /**
     * Creates a hierarchy whose artifacts are ordered as given; artifacts not given come after,
     * ordered by their paths.
     *
     * @param artifacts artifact paths, e.g. {@code g/a/v}, in order
     */
    public Hierarchy(List<String> artifacts) {
        final Map<String, Integer> o = new HashMap<>();
        for (String a : artifacts) {
            o.putIfAbsent(a, o.size());
        }
        this.order = Map.copyOf(o);
    }

    /**
     * Compares two artifacts by this hierarchy's order.
     *
     * @param a an artifact path
     * @param b another artifact path
     * @return negative if {@code a} comes first, zero if they are the same, positive otherwise
     */
    public int compare(String a, String b) {
        final Integer ra = order.get(a);
        final Integer rb = order.get(b);
        if (ra != null && rb != null) {
            return Integer.compare(ra, rb);
        }
        if (ra != null || rb != null) {
            return ra != null ? -1 : 1;
        }
        return a.compareTo(b);
    }

    /**
     * Records classes of no particular artifact, as {@link #add(String, Map)} with an empty
     * artifact path.
     *
     * @param infos class infos by internal name
     */
    public void add(Map<String, ClassInfo> infos) {
        add("", infos);
    }

    /**
     * Records the classes of an artifact. Of a class in several artifacts, the one of the artifact
     * that comes first in this hierarchy's order is resolved by default, so the result doesn't
     * depend on the order artifacts are recorded in; of the same artifact, the first one recorded.
     *
     * @param artifact the artifact path, e.g. {@code g/a/v}
     * @param infos class infos by internal name
     */
    public void add(String artifact, Map<String, ClassInfo> infos) {
        infos.forEach((name, info) -> {
            final Entry added = new Entry(artifact, info);
            final Entry before = classes.putIfAbsent(name, added);
            if (before == null) {
                return;
            }
            classes.merge(name, added, (kept, other) -> compare(kept.artifact(), other.artifact()) <= 0 ? kept : other);
            copies.compute(name, (k, list) -> {
                final List<Entry> all = list == null ? new ArrayList<>(List.of(before)) : new ArrayList<>(list);
                all.add(added);
                return all;
            });
        });
    }

    /**
     * Returns the class info of one artifact's copy of a class.
     *
     * @param artifact the artifact path
     * @param internalName the class's internal name
     * @return the copy's info, or {@code null} if the artifact has no copy of the class
     */
    public ClassInfo get(String artifact, String internalName) {
        final List<Entry> several = copies.get(internalName);
        if (several != null) {
            for (Entry e : several) {
                if (e.artifact().equals(artifact)) {
                    return e.info();
                }
            }
            return null;
        }
        final Entry e = classes.get(internalName);
        return e != null && e.artifact().equals(artifact) ? e.info() : null;
    }

    /**
     * Whether a class is in several artifacts, with the same contents or not.
     *
     * @param internalName the class's internal name
     * @return {@code true} if more than one artifact has a copy of it
     */
    public boolean inSeveralArtifacts(String internalName) {
        return copies.containsKey(internalName);
    }

    /**
     * Returns the artifacts containing a class, in this hierarchy's order.
     *
     * @param internalName the class's internal name
     * @return artifact paths; empty if the class isn't analyzed
     */
    public List<String> artifacts(String internalName) {
        final List<Entry> several = copies.get(internalName);
        if (several != null) {
            return several.stream().map(Entry::artifact).distinct().sorted(this::compare).toList();
        }
        final Entry e = classes.get(internalName);
        return e == null ? List.of() : List.of(e.artifact());
    }

    /**
     * The classes from one artifact's point of view: of a class in several artifacts with
     * different infos, the copy of the first artifact listed that has one, else the hierarchy's.
     *
     * @param preference artifact paths, in order of preference, e.g. the artifact itself and its
     *     dependencies
     * @return the view
     */
    public View view(List<String> preference) {
        return new View(preference);
    }

    /** The classes from one artifact's point of view; see {@link #view}. */
    public final class View {

        private final List<String> preference;

        private View(List<String> preference) {
            this.preference = List.copyOf(preference);
        }

        /**
         * Returns an analyzed class as this view resolves it.
         *
         * @param internalName the class's internal name
         * @return its info, or {@code null} if the class isn't analyzed
         */
        public ClassInfo get(String internalName) {
            final String artifact = artifactOf(internalName);
            if (artifact != null && copies.containsKey(internalName)) {
                return Hierarchy.this.get(artifact, internalName);
            }
            return Hierarchy.this.get(internalName);
        }

        /**
         * Whether an artifact has a copy of a class.
         *
         * @param artifact the artifact path
         * @param internalName the class's internal name
         * @return {@code true} if the artifact contains the class
         */
        public boolean inArtifact(String artifact, String internalName) {
            return Hierarchy.this.get(artifact, internalName) != null;
        }

        /**
         * Returns the artifact whose copy of a class this view sees: the first artifact listed
         * that has a copy, else the hierarchy's first.
         *
         * @param internalName the class's internal name
         * @return the artifact path, or {@code null} if the class isn't analyzed
         */
        public String artifactOf(String internalName) {
            final List<Entry> several = copies.get(internalName);
            if (several != null) {
                for (String a : preference) {
                    for (Entry e : several) {
                        if (e.artifact().equals(a)) {
                            return a;
                        }
                    }
                }
            }
            final Entry e = classes.get(internalName);
            return e == null ? null : e.artifact();
        }
    }

    /**
     * Returns the number of classes that are in several artifacts with different infos, for
     * logging.
     *
     * @return the number of classes
     */
    public int ambiguousClasses() {
        return (int) copies.values().stream().filter(Hierarchy::distinct).count();
    }

    /** Whether copies of a class differ. */
    private static boolean distinct(List<Entry> copies) {
        final ClassInfo first = copies.get(0).info();
        return copies.stream().anyMatch(e -> !e.info().equals(first));
    }

    /**
     * Returns an analyzed class.
     *
     * @param internalName the class's internal name
     * @return its info, or {@code null} if the class isn't analyzed
     */
    public ClassInfo get(String internalName) {
        final Entry e = classes.get(internalName);
        return e == null ? null : e.info();
    }

    /** The internal names of the analyzed classes; a live view. */
    Set<String> classNames() {
        return classes.keySet();
    }

    /**
     * Resolves a method to the class declaring it: along the superclass chain, as the JVM
     * resolves methods, then the interfaces, for default methods, taking the most specific one.
     *
     * @param methodKey {@code owner.name+descriptor}
     * @return the key with the declaring class as owner, or the key itself if no analyzed class
     *     declares the method
     */
    public String declaring(String methodKey) {
        return declaring(this::get, this::supertypes, methodKey);
    }

    /**
     * Resolves a method to the class declaring it, as an artifact sees the classes.
     *
     * @param view the artifact's view
     * @param methodKey {@code owner.name+descriptor}
     * @return the key with the declaring class as owner, or the key itself if no analyzed class
     *     declares the method
     */
    public String declaring(View view, String methodKey) {
        return declaring(view::get, n -> supertypes(view::get, n), methodKey);
    }

    private static String declaring(Function<String, ClassInfo> info, Function<String, List<String>> supertypes,
            String methodKey) {
        final int dot = methodKey.indexOf('.');
        final String owner = methodKey.substring(0, dot);
        final String member = methodKey.substring(dot + 1);
        for (String c = owner; c != null; ) {
            final ClassInfo ci = info.apply(c);
            if (ci == null) {
                break;
            }
            if (ci.methods().contains(member)) {
                return c + "." + member;
            }
            c = ci.superclass();
        }
        // then the interfaces: of default methods overriding each other, the most specific one,
        // i.e. not the one of an interface another declaring interface extends
        final List<String> declaring = new ArrayList<>();
        for (String t : supertypes.apply(owner)) {
            final ClassInfo ci = info.apply(t);
            if (ci != null && ci.methods().contains(member)) {
                declaring.add(t);
            }
        }
        for (String t : declaring) {
            if (declaring.stream().noneMatch(o -> !o.equals(t) && supertypes.apply(o).contains(t))) {
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
        return supertypes.computeIfAbsent(internalName, o -> supertypes(this::get, o));
    }

    /** The supertypes of a class as a lookup of class infos resolves them, nearest first. */
    private static List<String> supertypes(Function<String, ClassInfo> info, String internalName) {
        final List<String> result = new ArrayList<>();
        final Set<String> seen = new HashSet<>(Set.of(internalName));
        final Deque<String> todo = new ArrayDeque<>(List.of(internalName));
        while (!todo.isEmpty()) {
            final ClassInfo ci = info.apply(todo.poll());
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
    }
}
