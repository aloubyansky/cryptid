package io.github.aloubyansky.cryptid.bytecode;

import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Call;
import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Kind;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The calls between the methods of the analyzed classes of all artifacts: for every method, the
 * methods it calls, the methods its method handles (lambdas, method references) refer to, and the
 * classes it creates instances of.
 *
 * <p>A call is kept if it resolves to a method an analyzed class declares, along the superclass
 * chain and then the interfaces ({@link Hierarchy#declaring}); calls into classes that aren't
 * analyzed, such as the JDK's, aren't. Calls that run exactly the resolved method ({@code
 * invokestatic}, {@code invokespecial}) are {@link #exactCallees}; for the others, {@link
 * #virtualCallees} gives the declared method, and {@link #dispatch} the method an instance of a
 * given class runs for it.
 *
 * <p>Methods and types are identified by {@code int} ids, ascending in the order of their keys, so
 * a graph is the same however the artifacts were added.
 *
 * <p>Thread-safe while filling ({@link #addMethods}); call {@link #finish} once, after all classes
 * are in the {@link Hierarchy}, before any query.
 */
public final class CallGraph {

    private static final int[] NONE = {};

    /** A method's facts while filling: symbol ids shifted left by one, the low bit set for a method handle's target. */
    private record Raw(String artifact, int[] exact, int[] virtual, int[] instantiated) {}

    private final Set<String> analyzedClasses;
    private final Hierarchy hierarchy;

    private final Map<String, Integer> symbols = new ConcurrentHashMap<>();
    private final AtomicInteger nextSymbol = new AtomicInteger();
    private Map<String, Raw> raw = new ConcurrentHashMap<>();

    private String[] methodKeys;
    private String[] typeNames;
    private int[][] exact;
    private int[][] virtual;
    private int[][] instantiated;
    private long edges;
    private long handleEdges;
    private long instantiations;

    /**
     * Creates an empty graph.
     *
     * @param analyzedClasses internal names of all classes of all artifacts; only calls to these
     *     are kept
     * @param hierarchy the classes of all artifacts, complete by the time of {@link #finish}
     */
    public CallGraph(Set<String> analyzedClasses, Hierarchy hierarchy) {
        this.analyzedClasses = analyzedClasses;
        this.hierarchy = hierarchy;
    }

    /**
     * Records the facts of methods of no particular artifact, as {@link #addMethods(String, List)}
     * with an empty artifact path.
     *
     * @param methods the methods' facts
     */
    public void addMethods(List<MethodFacts> methods) {
        addMethods("", methods);
    }

    /**
     * Records the facts of an artifact's methods. Of a method in several artifacts, the facts of
     * the artifact that comes first in the hierarchy's order are kept, as {@link
     * Hierarchy#add(String, Map)} resolves the class, so a class's methods all come from the copy
     * the hierarchy resolves.
     *
     * @param artifact the artifact path, as given to the hierarchy
     * @param methods the methods' facts
     */
    public void addMethods(String artifact, List<MethodFacts> methods) {
        for (MethodFacts m : methods) {
            final Raw recorded = raw.get(m.method());
            if (recorded != null && hierarchy.compare(recorded.artifact(), artifact) <= 0) {
                continue;
            }
            final List<Integer> ex = new ArrayList<>();
            final List<Integer> vi = new ArrayList<>();
            for (Call c : m.calls()) {
                if (!analyzedClasses.contains(c.owner())) {
                    continue;
                }
                final int symbol = symbol(c.owner() + "." + c.name() + c.descriptor()) << 1 | (c.handle() ? 1 : 0);
                (c.kind() == Kind.STATIC || c.kind() == Kind.SPECIAL ? ex : vi).add(symbol);
            }
            final List<Integer> in = new ArrayList<>();
            for (String type : m.instantiated()) {
                if (analyzedClasses.contains(type)) {
                    in.add(symbol(type));
                }
            }
            raw.merge(m.method(), new Raw(artifact, ints(ex), ints(vi), ints(in)),
                    (kept, added) -> hierarchy.compare(kept.artifact(), added.artifact()) <= 0 ? kept : added);
        }
    }

    private int symbol(String key) {
        return symbols.computeIfAbsent(key, k -> nextSymbol.getAndIncrement());
    }

    private static int[] ints(List<Integer> list) {
        if (list.isEmpty()) {
            return NONE;
        }
        final int[] result = new int[list.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = list.get(i);
        }
        return result;
    }

    /** Resolves the recorded calls and assigns the ids. */
    public void finish() {
        typeNames = hierarchy.classNames().toArray(String[]::new);
        Arrays.sort(typeNames);
        final List<String> keys = new ArrayList<>();
        for (String type : typeNames) {
            for (String member : hierarchy.get(type).methods()) {
                keys.add(type + "." + member);
            }
        }
        methodKeys = keys.toArray(String[]::new);
        Arrays.sort(methodKeys);

        // symbol -> the id of the method it resolves to, or of the type it names; -1 for neither
        final int[] methodOf = new int[nextSymbol.get()];
        final int[] typeOf = new int[methodOf.length];
        symbols.forEach((key, symbol) -> {
            final boolean isMethod = key.indexOf('(') >= 0;
            methodOf[symbol] = isMethod ? method(hierarchy.declaring(key)) : -1;
            typeOf[symbol] = isMethod ? -1 : type(key);
        });

        exact = new int[methodKeys.length][];
        virtual = new int[methodKeys.length][];
        instantiated = new int[methodKeys.length][];
        Arrays.fill(exact, NONE);
        Arrays.fill(virtual, NONE);
        Arrays.fill(instantiated, NONE);
        for (int m = 0; m < methodKeys.length; m++) {
            final Raw r = raw.get(methodKeys[m]);
            if (r == null) {
                continue;
            }
            exact[m] = targets(r.exact(), methodOf);
            virtual[m] = targets(r.virtual(), methodOf);
            final int[] types = Arrays.stream(r.instantiated()).map(s -> typeOf[s]).filter(t -> t >= 0).sorted().distinct().toArray();
            instantiated[m] = types.length == 0 ? NONE : types;
            edges += exact[m].length + virtual[m].length;
            instantiations += types.length;
        }
        raw = null;
        symbols.clear();
    }

    /**
     * Resolves a method's recorded calls to method ids, sorted and distinct, counting those that
     * only method handles refer to.
     */
    private int[] targets(int[] recorded, int[] methodOf) {
        if (recorded.length == 0) {
            return NONE;
        }
        // target id shifted left by one; the low bit clear for a call, so a call sorts before a handle to the same target
        final long[] resolved = Arrays.stream(recorded)
                .filter(s -> methodOf[s >> 1] >= 0)
                .mapToLong(s -> (long) methodOf[s >> 1] << 1 | (s & 1))
                .sorted().toArray();
        final int[] result = new int[resolved.length];
        int n = 0;
        for (long r : resolved) {
            final int target = (int) (r >> 1);
            if (n > 0 && result[n - 1] == target) {
                continue;
            }
            result[n++] = target;
            handleEdges += r & 1;
        }
        return n == 0 ? NONE : Arrays.copyOf(result, n);
    }

    /**
     * Returns a method's id.
     *
     * @param key {@code owner.name+descriptor}
     * @return the id, or {@code -1} if no analyzed class declares the method
     */
    public int method(String key) {
        final int i = Arrays.binarySearch(methodKeys, key);
        return i < 0 ? -1 : i;
    }

    /**
     * Returns a method's key.
     *
     * @param method the method's id
     * @return {@code owner.name+descriptor}
     */
    public String methodKey(int method) {
        return methodKeys[method];
    }

    /**
     * Returns a class's id.
     *
     * @param internalName the class's internal name
     * @return the id, or {@code -1} if the class isn't analyzed
     */
    public int type(String internalName) {
        final int i = Arrays.binarySearch(typeNames, internalName);
        return i < 0 ? -1 : i;
    }

    /**
     * Returns a class's name.
     *
     * @param type the class's id
     * @return the internal name
     */
    public String typeName(int type) {
        return typeNames[type];
    }

    /**
     * The methods a method's static, constructor, private and {@code super} calls run, and those
     * its method handles of these kinds refer to.
     *
     * @param method the calling method's id
     * @return method ids, ascending and distinct; not to be modified
     */
    public int[] exactCallees(int method) {
        return exact[method];
    }

    /**
     * The methods a method's virtual and interface calls name, resolved to their declaring class,
     * and those its method handles of these kinds refer to. Which method runs depends on the
     * receiver's class: see {@link #dispatch}.
     *
     * @param method the calling method's id
     * @return method ids, ascending and distinct; not to be modified
     */
    public int[] virtualCallees(int method) {
        return virtual[method];
    }

    /**
     * The analyzed classes a method creates instances of.
     *
     * @param method the method's id
     * @return type ids, ascending and distinct; not to be modified
     */
    public int[] instantiated(int method) {
        return instantiated[method];
    }

    /**
     * The method an instance of a class runs when a method is called on it.
     *
     * @param type the id of the instance's class
     * @param declared the id of the called method, as in {@link #virtualCallees}
     * @return the id of the method that runs, or {@code -1} if the class isn't the method's class
     *     or a subtype of it, or inherits the method from a class that isn't analyzed
     */
    public int dispatch(int type, int declared) {
        final String key = methodKeys[declared];
        final int dot = key.indexOf('.');
        final String owner = key.substring(0, dot);
        final String name = typeNames[type];
        if (!name.equals(owner) && !hierarchy.supertypes(name).contains(owner)) {
            return -1;
        }
        return method(hierarchy.declaring(name + key.substring(dot)));
    }

    /**
     * Returns the number of methods of the analyzed classes.
     *
     * @return the number of methods
     */
    public int methodCount() {
        return methodKeys.length;
    }

    /**
     * Returns the number of calls kept, exact and virtual, distinct per calling method.
     *
     * @return the number of calls
     */
    public long edgeCount() {
        return edges;
    }

    /**
     * Returns the number of calls kept that only a method handle makes.
     *
     * @return the number of method handle targets
     */
    public long handleEdgeCount() {
        return handleEdges;
    }

    /**
     * Returns the number of instantiated classes kept, distinct per method.
     *
     * @return the number of instantiations
     */
    public long instantiationCount() {
        return instantiations;
    }
}
