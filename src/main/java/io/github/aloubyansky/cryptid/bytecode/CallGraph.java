package io.github.aloubyansky.cryptid.bytecode;

import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Call;
import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Kind;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * The calls between the methods of the analyzed classes of all artifacts: for every method, the
 * methods it calls, the methods its method handles (lambdas, method references) refer to, and the
 * classes it creates instances of.
 *
 * <p>A class in several artifacts, e.g. shaded into another, has a type for each copy, and each
 * copy has its own methods, with the calls of that copy. A call resolves as the calling artifact
 * sees the classes ({@link Hierarchy.View}): to the class declaring the method, along the
 * superclass chain and then the interfaces, and to the copy of it the artifact sees. Calls into
 * classes that aren't analyzed, such as the JDK's, aren't kept. Calls that run exactly the
 * resolved method ({@code invokestatic}, {@code invokespecial}) are {@link #exactCallees}; for the
 * others, {@link #virtualCallees} gives the declared method, and {@link #dispatch} the method an
 * instance of a given type runs for it.
 *
 * <p>Methods and types are identified by {@code int} ids, ordered by class, then by the
 * artifact's position in the class table's order, then by member, so a graph is the same however
 * the artifacts were added, and the methods of a type are a range of ids.
 *
 * <p>Thread-safe while filling ({@link #addMethods}); call {@link #finish} once, after all classes
 * are in the {@link Hierarchy}, before any query. Queries are thread-safe.
 */
public final class CallGraph {

    private static final int[] NONE = {};

    /** A method's facts while filling: symbol ids shifted left by one, the low bit set for a method handle's target. */
    private record Raw(int[] exact, int[] virtual, int[] instantiated) {}

    /** A method of one artifact's copy of a class, while filling. */
    private record CopyKey(String artifact, String method) {}

    private final Set<String> analyzedClasses;
    private final Hierarchy hierarchy;

    private final Map<String, Integer> symbols = new ConcurrentHashMap<>();
    private final AtomicInteger nextSymbol = new AtomicInteger();
    private Map<CopyKey, Raw> raw = new ConcurrentHashMap<>();

    // types: one per copy of a class
    private String[] artifactNames;
    private String[] typeNames;
    private int[] typeArtifact;
    private int[] typeSuperclass;
    private int[][] typeInterfaces;
    private int[] typeMethodsStart;
    private int[] typeMethodsEnd;
    /** class name -> the id of its first type; its other copies follow */
    private Map<String, Integer> firstType;
    private int[][] supertypeCache;

    // methods
    private String[] memberNames;
    private int[] methodType;
    private int[] methodMember;
    private int[][] exact;
    private int[][] virtual;
    private int[][] instantiated;
    private int[][] callers;
    private final Map<Long, Integer> dispatchCache = new ConcurrentHashMap<>();

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
     * Records the facts of an artifact's methods. Of a method recorded twice for the same
     * artifact, the first facts are kept.
     *
     * @param artifact the artifact path, as given to the hierarchy
     * @param methods the methods' facts
     */
    public void addMethods(String artifact, List<MethodFacts> methods) {
        for (MethodFacts m : methods) {
            final CopyKey key = new CopyKey(artifact, m.method());
            if (raw.containsKey(key)) {
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
            raw.putIfAbsent(key, new Raw(ints(ex), ints(vi), ints(in)));
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

    /**
     * Resolves the recorded calls and assigns the ids, each artifact seeing its own copy of a
     * class first, else the class table's first.
     */
    public void finish() {
        finish(artifact -> hierarchy.view(List.of(artifact)));
    }

    /**
     * Resolves the recorded calls and assigns the ids.
     *
     * @param views how each artifact, by path, sees the classes: which copy of a class in several
     *     artifacts its calls reach
     */
    public void finish(Function<String, Hierarchy.View> views) {
        // types, one per copy of a class, by class name and then the class table's order
        final String[] classNames = hierarchy.classNames().toArray(String[]::new);
        Arrays.sort(classNames);
        final List<String> artifacts = new ArrayList<>();
        final Map<String, Integer> artifactIds = new HashMap<>();
        final List<String> names = new ArrayList<>();
        final List<Integer> typeArtifacts = new ArrayList<>();
        firstType = new HashMap<>();
        for (String name : classNames) {
            firstType.put(name, names.size());
            for (String artifact : hierarchy.artifacts(name)) {
                names.add(name);
                typeArtifacts.add(artifactIds.computeIfAbsent(artifact, a -> {
                    artifacts.add(a);
                    return artifacts.size() - 1;
                }));
            }
        }
        artifactNames = artifacts.toArray(String[]::new);
        typeNames = names.toArray(String[]::new);
        typeArtifact = typeArtifacts.stream().mapToInt(Integer::intValue).toArray();
        final Hierarchy.View[] artifactViews = new Hierarchy.View[artifactNames.length];
        for (int a = 0; a < artifactNames.length; a++) {
            artifactViews[a] = views.apply(artifactNames[a]);
        }

        // members, ordered as their names, and the methods of each type, a range of ids
        final TreeSet<String> allMembers = new TreeSet<>();
        final ClassInfo[] infos = new ClassInfo[typeNames.length];
        for (int t = 0; t < typeNames.length; t++) {
            infos[t] = hierarchy.get(artifactNames[typeArtifact[t]], typeNames[t]);
            allMembers.addAll(infos[t].methods());
        }
        memberNames = allMembers.toArray(String[]::new);
        final Map<String, Integer> memberIds = new HashMap<>();
        for (int i = 0; i < memberNames.length; i++) {
            memberIds.put(memberNames[i], i);
        }
        typeMethodsStart = new int[typeNames.length];
        typeMethodsEnd = new int[typeNames.length];
        final List<Integer> types = new ArrayList<>();
        final List<Integer> members = new ArrayList<>();
        for (int t = 0; t < typeNames.length; t++) {
            typeMethodsStart[t] = members.size();
            for (int m : infos[t].methods().stream().mapToInt(memberIds::get).sorted().toArray()) {
                types.add(t);
                members.add(m);
            }
            typeMethodsEnd[t] = members.size();
        }
        methodType = types.stream().mapToInt(Integer::intValue).toArray();
        methodMember = members.stream().mapToInt(Integer::intValue).toArray();

        // supertypes, each as the type's artifact sees them
        typeSuperclass = new int[typeNames.length];
        typeInterfaces = new int[typeNames.length][];
        for (int t = 0; t < typeNames.length; t++) {
            final Hierarchy.View view = artifactViews[typeArtifact[t]];
            typeSuperclass[t] = infos[t].superclass() == null ? -1 : typeOf(view, infos[t].superclass());
            typeInterfaces[t] = infos[t].interfaces().stream().mapToInt(i -> typeOf(view, i)).filter(i -> i >= 0).toArray();
        }
        supertypeCache = new int[typeNames.length][];

        // calls, resolved as the calling artifact sees the classes
        final String[] symbolKeys = new String[nextSymbol.get()];
        symbols.forEach((key, symbol) -> symbolKeys[symbol] = key);
        final Resolver resolver = new Resolver(symbolKeys, artifactViews);
        exact = new int[methodType.length][];
        virtual = new int[methodType.length][];
        instantiated = new int[methodType.length][];
        final List<List<Integer>> callerLists = new ArrayList<>(methodType.length);
        for (int m = 0; m < methodType.length; m++) {
            callerLists.add(null);
        }
        for (int m = 0; m < methodType.length; m++) {
            final int artifact = typeArtifact[methodType[m]];
            final Raw r = raw.get(new CopyKey(artifactNames[artifact], methodKey(m)));
            if (r == null) {
                exact[m] = NONE;
                virtual[m] = NONE;
                instantiated[m] = NONE;
                continue;
            }
            exact[m] = targets(r.exact(), artifact, resolver);
            virtual[m] = targets(r.virtual(), artifact, resolver);
            final int[] in = Arrays.stream(r.instantiated()).map(s -> resolver.type(artifact, s)).filter(t -> t >= 0)
                    .sorted().distinct().toArray();
            instantiated[m] = in.length == 0 ? NONE : in;
            edges += exact[m].length + virtual[m].length;
            instantiations += in.length;
            addCallers(m, r, artifact, resolver, callerLists);
        }
        callers = new int[methodType.length][];
        for (int m = 0; m < methodType.length; m++) {
            final List<Integer> list = callerLists.get(m);
            callers[m] = list == null ? NONE : list.stream().mapToInt(Integer::intValue).sorted().distinct().toArray();
        }
        raw = null;
        symbols.clear();
    }

    /**
     * Resolves symbols to method and type ids as an artifact sees the classes. A symbol of no
     * class in several artifacts resolves the same for every artifact, once.
     */
    private final class Resolver {

        private final String[] symbolKeys;
        private final Hierarchy.View[] views;
        /** symbol -> its id for every artifact, or -2 if it depends on the artifact */
        private final int[] shared;
        private final Map<Long, Integer> perArtifact = new HashMap<>();

        Resolver(String[] symbolKeys, Hierarchy.View[] views) {
            this.symbolKeys = symbolKeys;
            this.views = views;
            this.shared = new int[symbolKeys.length];
            Arrays.fill(shared, Integer.MIN_VALUE);
        }

        /** The method a call symbol resolves to, as an artifact sees the classes, or -1. */
        int method(int artifact, int symbol) {
            return resolve(artifact, symbol, true);
        }

        /** The type an instantiation symbol names, as an artifact sees the classes, or -1. */
        int type(int artifact, int symbol) {
            return resolve(artifact, symbol, false);
        }

        private int resolve(int artifact, int symbol, boolean isMethod) {
            int s = shared[symbol];
            if (s == Integer.MIN_VALUE) {
                final String key = symbolKeys[symbol];
                final String owner = isMethod ? key.substring(0, key.indexOf('.')) : key;
                s = dependsOnArtifact(owner) ? -2 : isMethod ? CallGraph.this.method(hierarchy.declaring(key)) : CallGraph.this.type(key);
                shared[symbol] = s;
            }
            if (s != -2) {
                return s;
            }
            return perArtifact.computeIfAbsent((long) artifact << 32 | symbol, k -> {
                final Hierarchy.View view = views[artifact];
                final String key = symbolKeys[symbol];
                if (!isMethod) {
                    return typeOf(view, key);
                }
                final String declaring = hierarchy.declaring(view, key);
                final int dot = declaring.indexOf('.');
                final int type = typeOf(view, declaring.substring(0, dot));
                return type < 0 ? -1 : methodOf(type, declaring.substring(dot + 1));
            });
        }

        /** Whether a class or one of its supertypes is in several artifacts, so that resolving depends on who sees it. */
        private boolean dependsOnArtifact(String owner) {
            if (hierarchy.inSeveralArtifacts(owner)) {
                return true;
            }
            for (String t : hierarchy.supertypes(owner)) {
                if (hierarchy.inSeveralArtifacts(t)) {
                    return true;
                }
            }
            return false;
        }
    }

    /** The type of the copy of a class a view sees, or -1. */
    private int typeOf(Hierarchy.View view, String name) {
        final Integer first = firstType.get(name);
        if (first == null) {
            return -1;
        }
        final String artifact = view.artifactOf(name);
        for (int t = first; t < typeNames.length && typeNames[t].equals(name); t++) {
            if (artifactNames[typeArtifact[t]].equals(artifact)) {
                return t;
            }
        }
        return first;
    }

    /** A type's method of a member, or -1 if the type doesn't declare it. */
    private int methodOf(int type, String member) {
        final int m = Arrays.binarySearch(memberNames, member);
        return m < 0 ? -1 : methodOf(type, m);
    }

    private int methodOf(int type, int member) {
        final int i = Arrays.binarySearch(methodMember, typeMethodsStart[type], typeMethodsEnd[type], member);
        return i < 0 ? -1 : i;
    }

    /** Adds a method as the caller of the methods its calls resolve to; method handles aren't calls. */
    private void addCallers(int caller, Raw r, int artifact, Resolver resolver, List<List<Integer>> callerLists) {
        for (int[] recorded : new int[][] {r.exact(), r.virtual()}) {
            for (int s : recorded) {
                if ((s & 1) != 0) {
                    continue;
                }
                final int target = resolver.method(artifact, s >> 1);
                if (target >= 0) {
                    List<Integer> list = callerLists.get(target);
                    if (list == null) {
                        list = new ArrayList<>(2);
                        callerLists.set(target, list);
                    }
                    list.add(caller);
                }
            }
        }
    }

    /**
     * Resolves a method's recorded calls to method ids, sorted and distinct, counting those that
     * only method handles refer to.
     */
    private int[] targets(int[] recorded, int artifact, Resolver resolver) {
        if (recorded.length == 0) {
            return NONE;
        }
        // target id shifted left by one; the low bit clear for a call, so a call sorts before a handle to the same target
        final long[] resolved = Arrays.stream(recorded)
                .mapToLong(s -> {
                    final int target = resolver.method(artifact, s >> 1);
                    return target < 0 ? -1 : (long) target << 1 | (s & 1);
                })
                .filter(r -> r >= 0)
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
     * Returns the id of a method of the first artifact's copy of its class.
     *
     * @param key {@code owner.name+descriptor}
     * @return the id, or {@code -1} if no analyzed class declares the method
     */
    public int method(String key) {
        final int dot = key.indexOf('.');
        final int type = type(key.substring(0, dot));
        return type < 0 ? -1 : methodOf(type, key.substring(dot + 1));
    }

    /**
     * Returns the id of a method of one artifact's copy of its class.
     *
     * @param artifact the artifact path
     * @param key {@code owner.name+descriptor}
     * @return the id, or {@code -1} if the artifact's copy doesn't declare the method
     */
    public int method(String artifact, String key) {
        final int dot = key.indexOf('.');
        final int type = type(artifact, key.substring(0, dot));
        return type < 0 ? -1 : methodOf(type, key.substring(dot + 1));
    }

    /**
     * Returns the ids of a method in every copy of its class.
     *
     * @param key {@code owner.name+descriptor}
     * @return the ids, ascending; empty if no analyzed class declares the method
     */
    public int[] methods(String key) {
        final int dot = key.indexOf('.');
        final String owner = key.substring(0, dot);
        final Integer first = firstType.get(owner);
        if (first == null) {
            return NONE;
        }
        final List<Integer> result = new ArrayList<>(1);
        for (int t = first; t < typeNames.length && typeNames[t].equals(owner); t++) {
            final int m = methodOf(t, key.substring(dot + 1));
            if (m >= 0) {
                result.add(m);
            }
        }
        return result.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Returns a method's key.
     *
     * @param method the method's id
     * @return {@code owner.name+descriptor}
     */
    public String methodKey(int method) {
        return typeNames[methodType[method]] + "." + memberNames[methodMember[method]];
    }

    /**
     * Returns the artifact of a method's copy of its class.
     *
     * @param method the method's id
     * @return the artifact path
     */
    public String artifact(int method) {
        return artifactNames[typeArtifact[methodType[method]]];
    }

    /**
     * Returns the type of a method, the copy of its class it belongs to.
     *
     * @param method the method's id
     * @return the type's id
     */
    public int typeOfMethod(int method) {
        return methodType[method];
    }

    /**
     * Returns the id of the first artifact's copy of a class.
     *
     * @param internalName the class's internal name
     * @return the id, or {@code -1} if the class isn't analyzed
     */
    public int type(String internalName) {
        final Integer first = firstType.get(internalName);
        return first == null ? -1 : first;
    }

    /**
     * Returns the id of one artifact's copy of a class.
     *
     * @param artifact the artifact path
     * @param internalName the class's internal name
     * @return the id, or {@code -1} if the artifact has no copy of the class
     */
    public int type(String artifact, String internalName) {
        final Integer first = firstType.get(internalName);
        if (first == null) {
            return -1;
        }
        for (int t = first; t < typeNames.length && typeNames[t].equals(internalName); t++) {
            if (artifactNames[typeArtifact[t]].equals(artifact)) {
                return t;
            }
        }
        return -1;
    }

    /**
     * Returns a type's class name.
     *
     * @param type the type's id
     * @return the internal name
     */
    public String typeName(int type) {
        return typeNames[type];
    }

    /**
     * Returns the artifact of a type, a copy of a class.
     *
     * @param type the type's id
     * @return the artifact path
     */
    public String typeArtifact(int type) {
        return artifactNames[typeArtifact[type]];
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
     * receiver's type: see {@link #dispatch}.
     *
     * @param method the calling method's id
     * @return method ids, ascending and distinct; not to be modified
     */
    public int[] virtualCallees(int method) {
        return virtual[method];
    }

    /**
     * The methods calling a method, by a call resolving to it: the method's declaring class, not
     * the class a virtual call may dispatch to. Method handles don't count.
     *
     * @param method the called method's id
     * @return method ids, ascending and distinct; not to be modified
     */
    public int[] callers(int method) {
        return callers[method];
    }

    /**
     * The analyzed types a method creates instances of.
     *
     * @param method the method's id
     * @return type ids, ascending and distinct; not to be modified
     */
    public int[] instantiated(int method) {
        return instantiated[method];
    }

    /**
     * The supertypes of a type, superclasses and interfaces, transitively, as its artifact sees
     * them.
     *
     * @param type the type's id
     * @return type ids, ascending and distinct, without the type itself; not to be modified
     */
    public int[] supertypes(int type) {
        int[] s = supertypeCache[type];
        if (s == null) {
            final TreeSet<Integer> result = new TreeSet<>();
            final Deque<Integer> todo = new ArrayDeque<>(List.of(type));
            while (!todo.isEmpty()) {
                final int t = todo.pop();
                if (typeSuperclass[t] >= 0 && result.add(typeSuperclass[t])) {
                    todo.add(typeSuperclass[t]);
                }
                for (int i : typeInterfaces[t]) {
                    if (result.add(i)) {
                        todo.add(i);
                    }
                }
            }
            result.remove(type);
            s = result.stream().mapToInt(Integer::intValue).toArray();
            supertypeCache[type] = s;
        }
        return s;
    }

    /**
     * The method an instance of a type runs when a method is called on it: along the type's
     * superclass chain, then its interfaces, taking the most specific default method.
     *
     * @param type the id of the instance's type
     * @param declared the id of the called method, as in {@link #virtualCallees}
     * @return the id of the method that runs, or {@code -1} if the type isn't the method's type
     *     or a subtype of it, or inherits the method from a class that isn't analyzed
     */
    public int dispatch(int type, int declared) {
        final int owner = methodType[declared];
        if (type != owner && Arrays.binarySearch(supertypes(type), owner) < 0) {
            return -1;
        }
        final int member = methodMember[declared];
        return dispatchCache.computeIfAbsent((long) type << 32 | member, k -> implementation(type, member));
    }

    private int implementation(int type, int member) {
        for (int t = type; t >= 0; t = typeSuperclass[t]) {
            final int m = methodOf(t, member);
            if (m >= 0) {
                return m;
            }
        }
        // the interfaces: of default methods overriding each other, the most specific one
        final List<Integer> declaring = new ArrayList<>();
        for (int t : supertypes(type)) {
            if (methodOf(t, member) >= 0) {
                declaring.add(t);
            }
        }
        for (int t : declaring) {
            if (declaring.stream().noneMatch(o -> o != t && Arrays.binarySearch(supertypes(o), t) >= 0)) {
                return methodOf(t, member);
            }
        }
        return -1;
    }

    /**
     * The method an instance of a type runs for a member, along its superclass chain and then its
     * interfaces, as {@link #dispatch} does for a declared method.
     *
     * @param type the id of the instance's type
     * @param member {@code name+descriptor}
     * @return the method's id, or {@code -1} if no analyzed supertype declares it
     */
    public int implementation(int type, String member) {
        final int m = Arrays.binarySearch(memberNames, member);
        return m < 0 ? -1 : dispatchCache.computeIfAbsent((long) type << 32 | m, k -> implementation(type, m));
    }

    /**
     * The static initializer of a type.
     *
     * @param type the type's id
     * @return the id of its {@code <clinit>}, or {@code -1} if it has none
     */
    public int staticInitializer(int type) {
        return methodOf(type, "<clinit>()V");
    }

    /**
     * The methods a type declares.
     *
     * @param type the type's id
     * @return the ids of its methods, ascending
     */
    public int[] declaredMethods(int type) {
        final int[] result = new int[typeMethodsEnd[type] - typeMethodsStart[type]];
        for (int i = 0; i < result.length; i++) {
            result[i] = typeMethodsStart[type] + i;
        }
        return result;
    }

    /**
     * The member of a method, without its class.
     *
     * @param method the method's id
     * @return {@code name+descriptor}
     */
    public String member(int method) {
        return memberNames[methodMember[method]];
    }

    /**
     * Returns the ids of every copy of a class.
     *
     * @param internalName the class's internal name
     * @return the type ids, ascending; empty if the class isn't analyzed
     */
    public int[] types(String internalName) {
        final Integer first = firstType.get(internalName);
        if (first == null) {
            return NONE;
        }
        int end = first;
        while (end < typeNames.length && typeNames[end].equals(internalName)) {
            end++;
        }
        final int[] result = new int[end - first];
        for (int i = 0; i < result.length; i++) {
            result[i] = first + i;
        }
        return result;
    }

    /**
     * Returns the number of types: copies of analyzed classes.
     *
     * @return the number of types
     */
    public int typeCount() {
        return typeNames.length;
    }

    /**
     * Returns the number of methods of the analyzed classes, counted per copy.
     *
     * @return the number of methods
     */
    public int methodCount() {
        return methodType.length;
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
