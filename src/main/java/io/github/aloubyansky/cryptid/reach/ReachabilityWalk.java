package io.github.aloubyansky.cryptid.reach;

import io.github.aloubyansky.cryptid.EntryPoint;
import io.github.aloubyansky.cryptid.MethodId;
import io.github.aloubyansky.cryptid.bytecode.CallGraph;
import io.github.aloubyansky.cryptid.bytecode.ClassInfo;
import io.github.aloubyansky.cryptid.bytecode.Hierarchy;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.ArtifactPaths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Walks the call graph from an application's entry points, to tell which methods it reaches and
 * from which entry points.
 *
 * <p>The walk is breadth first from the roots, growing the set of instantiated types as it goes:
 *
 * <ol>
 *   <li>a reached method's exact calls reach their targets;
 *   <li>its virtual and interface calls reach the method each instantiated subtype of the declared
 *       type runs, including types instantiated later;
 *   <li>its method handles reach their targets when it creates them;
 *   <li>the types it instantiates are instantiated, and a reached method's type's static
 *       initializer is reached;
 *   <li>an instantiated type's methods that override a method of a JDK supertype are reached,
 *       since the JDK calls them, e.g. {@code Runnable.run};
 *   <li>an instantiated type's callbacks, e.g. a JAX-RS sub-resource's methods, become entry
 *       points of their own.
 * </ol>
 *
 * Types the runtime instantiates, e.g. beans, are instantiated at the start, and their
 * constructors reached by the runtime, with no entry point. Each reached method keeps the entry
 * point it was first reached from and its predecessor, which gives a shortest path. Then the sets
 * of entry points reaching each method are propagated along the same edges to a fixpoint.
 *
 * <p>Not thread-safe; a walk is used once.
 */
public final class ReachabilityWalk {

    /** No entry point: reached by the runtime, e.g. a bean's constructor. */
    private static final int RUNTIME = -1;

    private final CallGraph graph;
    private final Hierarchy hierarchy;

    /** The entry points: the roots, then the callbacks as they become entry points. */
    private final List<EntryPoint> entryPoints = new ArrayList<>();
    private final List<int[]> entryMethods = new ArrayList<>();
    /** class internal name -> its callbacks, not yet entry points */
    private final Map<String, List<EntryPoint>> pendingCallbacks;

    private final int[] origin;
    private final int[] predecessor;
    private final int[] depth;
    private final BitSet reached;
    private final BitSet instantiated;
    private final BitSet initialized;
    private final Deque<Integer> queue = new ArrayDeque<>();
    /** declared type -> the virtual calls on it: declared method and calling method */
    private final Map<Integer, List<long[]>> virtualCalls = new HashMap<>();
    /** supertype -> the instantiated types that are it or its subtypes */
    private final Map<Integer, List<Integer>> instantiatedSubtypes = new HashMap<>();
    /** method -> the methods it leads to, for propagating the sets */
    private final Map<Integer, Set<Integer>> successors = new HashMap<>();

    /**
     * Prepares a walk.
     *
     * @param graph the call graph, finished
     * @param hierarchy the class table, for JDK supertypes
     * @param roots the root entry points
     * @param callbacks entry points the framework calls on instances, by the internal name of
     *     their class
     */
    public ReachabilityWalk(CallGraph graph, Hierarchy hierarchy, List<EntryPoint> roots, Map<String, List<EntryPoint>> callbacks) {
        this.graph = graph;
        this.hierarchy = hierarchy;
        this.pendingCallbacks = new HashMap<>(callbacks);
        final int n = graph.methodCount();
        this.origin = new int[n];
        this.predecessor = new int[n];
        this.depth = new int[n];
        Arrays.fill(predecessor, -1);
        this.reached = new BitSet(n);
        this.instantiated = new BitSet(graph.typeCount());
        this.initialized = new BitSet(graph.typeCount());
        roots.forEach(this::addEntryPoint);
    }

    /**
     * What the walk found.
     *
     * @param entryPoints the entry points: the roots, then the callbacks that became entry points,
     *     in the order they did
     * @param reachedMethods the number of methods reached
     * @param instantiatedTypes the number of types instantiated
     */
    public record Summary(List<EntryPoint> entryPoints, int reachedMethods, int instantiatedTypes) {}

    /**
     * Walks.
     *
     * @param runtimeInstantiated internal names of classes the runtime instantiates, e.g. beans
     * @return what was found
     */
    public Summary walk(Set<String> runtimeInstantiated) {
        for (String name : new TreeSet<>(runtimeInstantiated)) {
            for (int t : graph.types(name)) {
                instantiate(t, RUNTIME, -1);
                for (int m : graph.declaredMethods(t)) {
                    if (graph.member(m).startsWith("<init>")) {
                        reach(m, RUNTIME, -1);
                    }
                }
            }
        }
        for (int e = 0; e < entryPoints.size(); e++) {
            for (int m : entryMethods.get(e)) {
                reach(m, e, -1);
            }
        }
        while (!queue.isEmpty()) {
            process(queue.poll());
        }
        propagate();
        return new Summary(List.copyOf(entryPoints), reached.cardinality(), instantiated.cardinality());
    }

    private void addEntryPoint(EntryPoint e) {
        final String key = e.method().className().replace('.', '/') + "." + e.method().name() + e.method().descriptor();
        final int[] methods = e.artifact().isPresent()
                ? new int[] {graph.method(ArtifactPaths.of(e.artifact().get()), key)}
                : graph.methods(key);
        entryPoints.add(e);
        entryMethods.add(Arrays.stream(methods).filter(m -> m >= 0).toArray());
    }

    private void reach(int method, int from, int pred) {
        if (method < 0 || reached.get(method)) {
            if (method >= 0 && pred >= 0) {
                successors.computeIfAbsent(pred, k -> new LinkedHashSet<>()).add(method);
            }
            return;
        }
        reached.set(method);
        origin[method] = from;
        predecessor[method] = pred;
        depth[method] = pred < 0 ? 0 : depth[pred] + 1;
        if (pred >= 0) {
            successors.computeIfAbsent(pred, k -> new LinkedHashSet<>()).add(method);
        }
        queue.add(method);
    }

    private void process(int m) {
        final int from = origin[m];
        final int type = graph.typeOfMethod(m);
        if (!initialized.get(type)) {
            initialized.set(type);
            reach(graph.staticInitializer(type), from, m);
        } else {
            final int clinit = graph.staticInitializer(type);
            if (clinit >= 0 && clinit != m) {
                successors.computeIfAbsent(m, k -> new LinkedHashSet<>()).add(clinit);
            }
        }
        for (int callee : graph.exactCallees(m)) {
            reach(callee, from, m);
        }
        for (int declared : graph.virtualCallees(m)) {
            final int owner = graph.typeOfMethod(declared);
            virtualCalls.computeIfAbsent(owner, k -> new ArrayList<>()).add(new long[] {declared, m});
            for (int t : instantiatedSubtypes.getOrDefault(owner, List.of())) {
                reach(graph.dispatch(t, declared), from, m);
            }
        }
        for (int t : graph.instantiated(m)) {
            instantiate(t, from, m);
        }
    }

    private void instantiate(int type, int from, int pred) {
        if (instantiated.get(type)) {
            if (pred >= 0) {
                // the instantiating method leads to what instantiating the type reaches
                for (int m : jdkOverrides(type)) {
                    successors.computeIfAbsent(pred, k -> new LinkedHashSet<>()).add(m);
                }
            }
            return;
        }
        instantiated.set(type);
        final List<Integer> supers = new ArrayList<>();
        supers.add(type);
        for (int s : graph.supertypes(type)) {
            supers.add(s);
        }
        for (int s : supers) {
            instantiatedSubtypes.computeIfAbsent(s, k -> new ArrayList<>()).add(type);
            for (long[] call : virtualCalls.getOrDefault(s, List.of())) {
                final int caller = (int) call[1];
                reach(graph.dispatch(type, (int) call[0]), origin[caller], caller);
            }
        }
        for (int m : jdkOverrides(type)) {
            reach(m, from, pred);
        }
        // its callbacks become entry points
        final List<EntryPoint> callbacks = pendingCallbacks.remove(graph.typeName(type));
        if (callbacks != null) {
            for (EntryPoint cb : callbacks) {
                addEntryPoint(cb);
                final int e = entryPoints.size() - 1;
                for (int m : entryMethods.get(e)) {
                    reach(m, e, -1);
                }
            }
        }
    }

    private final Map<Integer, int[]> jdkOverrideCache = new HashMap<>();

    /** The methods an instance of a type runs for the instance methods its JDK supertypes declare. */
    private int[] jdkOverrides(int type) {
        return jdkOverrideCache.computeIfAbsent(type, t -> {
            final Set<String> members = new HashSet<>();
            final Hierarchy.View view = hierarchy.view(List.of(graph.typeArtifact(t)));
            final Deque<String> todo = new ArrayDeque<>(List.of(graph.typeName(t)));
            final Set<String> seen = new HashSet<>();
            while (!todo.isEmpty()) {
                final String name = todo.pop();
                if (!seen.add(name)) {
                    continue;
                }
                final ClassInfo info = view.get(name);
                if (info == null) {
                    members.addAll(Types.jdkMembers(name));
                    continue;
                }
                todo.add(info.superclass() == null ? "java/lang/Object" : info.superclass());
                todo.addAll(info.interfaces());
            }
            final Set<Integer> result = new TreeSet<>();
            for (String member : members) {
                final int m = graph.implementation(t, member);
                if (m >= 0) {
                    result.add(m);
                }
            }
            return result.stream().mapToInt(Integer::intValue).toArray();
        });
    }

    /** The sets of entry points reaching each method, propagated along the edges to a fixpoint. */
    private BitSet[] sets;

    private void propagate() {
        sets = new BitSet[graph.methodCount()];
        final Deque<Integer> work = new ArrayDeque<>();
        for (int e = 0; e < entryPoints.size(); e++) {
            for (int m : entryMethods.get(e)) {
                if (sets[m] == null) {
                    sets[m] = new BitSet();
                }
                sets[m].set(e);
                work.add(m);
            }
        }
        // virtual calls reach every instantiated subtype's method, also those instantiated after the call was seen
        virtualCalls.forEach((owner, calls) -> {
            for (long[] call : calls) {
                for (int t : instantiatedSubtypes.getOrDefault(owner, List.of())) {
                    final int target = graph.dispatch(t, (int) call[0]);
                    if (target >= 0) {
                        successors.computeIfAbsent((int) call[1], k -> new LinkedHashSet<>()).add(target);
                    }
                }
            }
        });
        while (!work.isEmpty()) {
            final int m = work.poll();
            for (int s : successors.getOrDefault(m, Set.of())) {
                if (sets[s] == null) {
                    sets[s] = new BitSet();
                }
                final int before = sets[s].cardinality();
                sets[s].or(sets[m]);
                if (sets[s].cardinality() != before) {
                    work.add(s);
                }
            }
        }
    }

    /**
     * Whether a method is reached.
     *
     * @param method the method's id
     * @return {@code true} if reached
     */
    public boolean isReached(int method) {
        return method >= 0 && reached.get(method);
    }

    /**
     * The entry points reaching a method.
     *
     * @param method the method's id
     * @return the entry points, in order; empty if none, also for a method only the runtime reaches
     */
    public List<EntryPoint> entryPointsOf(int method) {
        if (sets == null || sets[method] == null) {
            return List.of();
        }
        final List<EntryPoint> result = new ArrayList<>();
        sets[method].stream().forEach(e -> result.add(entryPoints.get(e)));
        return result;
    }

    /**
     * A shortest path to a method, from the entry point it was first reached from.
     *
     * @param method the method's id
     * @return the methods, the entry point's first; empty if not reached
     */
    public List<MethodId> pathTo(int method) {
        if (!isReached(method)) {
            return List.of();
        }
        final List<MethodId> path = new ArrayList<>();
        for (int m = method; m >= 0; m = predecessor[m]) {
            final String key = graph.methodKey(m);
            final int dot = key.indexOf('.');
            final int paren = key.indexOf('(');
            path.add(0, new MethodId(key.substring(0, dot).replace('/', '.'), key.substring(dot + 1, paren), key.substring(paren)));
        }
        return path;
    }
}
