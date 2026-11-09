package io.github.aloubyansky.cryptid.detection;

import io.github.aloubyansky.cryptid.bytecode.AVal;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallSite;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * The crypto objects of a set of methods, typically a JAR's, and the calls to specified crypto
 * APIs that create them or are invoked on them, including across methods: the facts detection
 * works from.
 *
 * <p>An object is abstract: it stands for all instances created at one site, as in points-to
 * analysis. Its origin is the id of that site in {@link AVal#origins()}: the {@code new} for a
 * constructor call, or the call for a method returning an object, e.g. {@code
 * Cipher.getInstance}. A call creates the object of its own site, and is an event of every other
 * object its receiver may be; a constructor, which runs on the object its {@code new} allocated,
 * is that object's creation only.
 *
 * <p>Objects are followed across the methods of the graph:
 *
 * <ul>
 *   <li><b>into callees</b>: an object passed as argument {@code k} to one of the methods is that
 *       method's parameter {@code k}, so the calls on that parameter are events of the object,
 *       e.g. {@code init} in a {@code configure(Cipher c)} helper;
 *   <li><b>out to callers</b>: an object a method returns is the object its callers receive, so
 *       their calls on it are events of the object, e.g. {@code init} after {@code Cipher c =
 *       create()}.
 * </ul>
 *
 * <p>Calls reached in another method carry the {@link Path} of call sites followed into callees,
 * so that a parameter used there resolves to the argument of the caller the object came from,
 * not of every caller, and a returned object goes back to that caller only. Where the path is
 * empty (the method of the call being resolved), a returned object goes to all callers in the
 * graph, but a parameter isn't resolved: each caller passing an object in is a finding of its own,
 * entering the method on its path. Callees are matched by exact method signature; calls
 * dispatched to an overriding method, and methods outside the graph, aren't followed. At most
 * {@value #MAX_HOPS} hops are followed.
 */
public final class CryptoObjectGraph {

    /** Calls between methods followed at most, into callees and out to callers together. */
    static final int MAX_HOPS = 4;

    /**
     * A call to a specified crypto API.
     *
     * @param site the call site
     * @param spec the API's spec
     */
    public record CryptoApiCall(CallSite site, ApiSpec spec) {}

    /**
     * An abstract crypto object.
     *
     * @param method the method creating it, {@code owner.name+descriptor}
     * @param origin the id of the site creating it, within that method
     * @param creations the calls to specified APIs creating it, in bytecode order; empty if it's
     *     created by code without a spec, e.g. a helper method
     * @param events the calls to specified APIs invoked on it in that method, in bytecode order
     */
    public record CryptoObject(String method, int origin, List<CryptoApiCall> creations, List<CryptoApiCall> events) {}

    /**
     * The call sites followed into callees to reach a call, outermost first.
     *
     * @param frames the call sites; empty for the method of the call being resolved
     */
    public record Path(List<CallSite> frames) {

        /** No call followed. */
        public static final Path ROOT = new Path(List.of());

        /**
         * Follows a call into its callee.
         *
         * @param cs the call
         * @return this path with the call appended
         */
        Path enter(CallSite cs) {
            final List<CallSite> f = new ArrayList<>(frames);
            f.add(cs);
            return new Path(List.copyOf(f));
        }

        /**
         * The innermost call followed.
         *
         * @return the last call site; the path must not be the root
         */
        CallSite top() {
            return frames.get(frames.size() - 1);
        }

        /**
         * Returns from the innermost call followed.
         *
         * @return this path without its last call site; the path must not be the root
         */
        Path leave() {
            return new Path(frames.subList(0, frames.size() - 1));
        }

        /**
         * Whether no call was followed.
         *
         * @return {@code true} for the method of the call being resolved
         */
        boolean isRoot() {
            return frames.isEmpty();
        }
    }

    /**
     * A call reached from an object, with the path it was reached by.
     *
     * @param call the call
     * @param path the call sites followed into callees to reach it
     */
    public record Reached(CryptoApiCall call, Path path) {}

    private final List<CryptoApiCall> calls = new ArrayList<>();
    private final Map<String, Analyzer.MethodResult> methods = new LinkedHashMap<>();
    private final Map<String, Map<Integer, CryptoObject>> objects = new LinkedHashMap<>();
    /** method -> parameter index -> calls to specified APIs invoked on that parameter */
    private final Map<String, Map<Integer, List<CryptoApiCall>>> parameterEvents = new LinkedHashMap<>();
    /** method -> the call sites in the graph calling it */
    private final Map<String, List<CallSite>> callers = new LinkedHashMap<>();
    /** The objects a value refers to: origins in its method, and the method's parameters. */
    private record Refs(Set<Integer> origins, long params) {}

    /**
     * method -> the results of calls returning their receiver -> the receiver's objects, e.g. the
     * builder {@code setProvider} returns
     */
    private final Map<String, Map<Integer, Refs>> receivers = new LinkedHashMap<>();
    /** A call's position in {@link #calls}, for returning calls of a method in bytecode order. */
    private final Map<CryptoApiCall, Integer> positions = new IdentityHashMap<>();

    private CryptoObjectGraph(List<Analyzer.MethodResult> results, CryptoApiMatcher matcher, Types types) {
        results.forEach(m -> methods.put(m.method(), m));
        for (Analyzer.MethodResult m : results) {
            final Map<Integer, List<CryptoApiCall>> creations = new TreeMap<>();
            final Map<Integer, List<CryptoApiCall>> events = new TreeMap<>();
            final Map<Integer, Refs> returned = new HashMap<>();
            for (CallSite cs : m.calls()) {
                final Analyzer.MethodResult callee = methods.get(signature(cs));
                if (callee != null) {
                    callers.computeIfAbsent(callee.method(), k -> new ArrayList<>()).add(cs);
                }
                final List<ApiSpec> specs = matcher.match(cs, types);
                // calls run in bytecode order, so the receiver's own receivers are known
                final Refs receiver = expand(returned, cs.receiver().origins(), cs.receiver().params());
                if (cs.created() >= 0 && specs.stream().anyMatch(ApiSpec::returnsReceiver)) {
                    returned.put(cs.created(), receiver);
                }
                for (ApiSpec spec : specs) {
                    final CryptoApiCall c = new CryptoApiCall(cs, spec);
                    positions.put(c, calls.size());
                    calls.add(c);
                    if (cs.created() >= 0 && !returned.containsKey(cs.created())) {
                        creations.computeIfAbsent(cs.created(), k -> new ArrayList<>()).add(c);
                    }
                    for (int origin : receiver.origins()) {
                        // a constructor runs on the object its new allocated: that's its creation, not an event
                        if (origin != cs.created()) {
                            events.computeIfAbsent(origin, k -> new ArrayList<>()).add(c);
                        }
                    }
                    for (int p : bits(receiver.params())) {
                        parameterEvents.computeIfAbsent(m.method(), k -> new TreeMap<>())
                                .computeIfAbsent(p, k -> new ArrayList<>()).add(c);
                    }
                }
            }
            final Map<Integer, CryptoObject> objs = new LinkedHashMap<>();
            final Set<Integer> origins = new java.util.TreeSet<>(creations.keySet());
            origins.addAll(events.keySet());
            for (int o : origins) {
                objs.put(o, new CryptoObject(m.method(), o, List.copyOf(creations.getOrDefault(o, List.of())),
                        List.copyOf(events.getOrDefault(o, List.of()))));
            }
            if (!objs.isEmpty()) {
                objects.put(m.method(), Collections.unmodifiableMap(objs));
            }
            if (!returned.isEmpty()) {
                receivers.put(m.method(), returned);
            }
        }
    }

    /** The objects of origins and parameters, with results of calls returning their receiver replaced by it. */
    private static Refs expand(Map<Integer, Refs> returned, Set<Integer> origins, long params) {
        if (returned.isEmpty() || origins.stream().noneMatch(returned::containsKey)) {
            return new Refs(origins, params);
        }
        final Set<Integer> result = new java.util.TreeSet<>();
        long p = params;
        for (int o : origins) {
            final Refs r = returned.get(o);
            if (r == null) {
                result.add(o);
            } else {
                result.addAll(r.origins());
                p |= r.params();
            }
        }
        return new Refs(result, p);
    }

    /**
     * Builds the graph of one method.
     *
     * @param method the method's call sites
     * @param matcher the spec matcher
     * @param types the class hierarchy, for specs matching subtypes
     * @return the graph
     */
    public static CryptoObjectGraph of(Analyzer.MethodResult method, CryptoApiMatcher matcher, Types types) {
        return new CryptoObjectGraph(List.of(method), matcher, types);
    }

    /**
     * Builds the graph of methods, following objects between them.
     *
     * @param methods the methods, e.g. a JAR's
     * @param matcher the spec matcher
     * @param types the class hierarchy, for specs matching subtypes
     * @return the graph
     */
    public static CryptoObjectGraph of(List<Analyzer.MethodResult> methods, CryptoApiMatcher matcher, Types types) {
        return new CryptoObjectGraph(methods, matcher, types);
    }

    /**
     * All calls to specified APIs.
     *
     * @return the calls, by method and then in bytecode order; a call matching several specs once
     *     per spec
     */
    public List<CryptoApiCall> calls() {
        return Collections.unmodifiableList(calls);
    }

    /**
     * The calls that report findings on their own.
     *
     * @return the calls to root APIs, by method and then in bytecode order
     */
    public List<CryptoApiCall> roots() {
        return calls.stream().filter(c -> c.spec().root()).toList();
    }

    /**
     * The objects created by, or acted on by, calls to specified APIs.
     *
     * @return the objects, by method and then by origin
     */
    public Collection<CryptoObject> objects() {
        final List<CryptoObject> result = new ArrayList<>();
        objects.values().forEach(m -> result.addAll(m.values()));
        return result;
    }

    /**
     * Returns an object.
     *
     * @param method the method creating it
     * @param origin the id of the site creating it
     * @return the object, or empty if no call to a specified API in that method creates it or
     *     acts on it
     */
    public Optional<CryptoObject> object(String method, int origin) {
        return Optional.ofNullable(objects.getOrDefault(method, Map.of()).get(origin));
    }

    /**
     * Returns the calls of the objects a value of a call may be: the calls creating them and their
     * events, in the call's method and, following the objects, in other methods.
     *
     * @param at the call whose value it is, giving the method the value belongs to
     * @param value the value: its origins are objects of that method, its parameters those of the
     *     method
     * @param path the path {@code at} was reached by
     * @return the calls, each once: those of the call's method in bytecode order, then those of
     *     other methods
     */
    public List<Reached> related(CallSite at, AVal value, Path path) {
        return related(at, value.origins(), value.params(), path);
    }

    /**
     * Returns the calls of the object a call creates: the call itself and its events, in its
     * method and in other methods.
     *
     * @param at the call
     * @param path the path {@code at} was reached by
     * @return the calls, as for {@link #related(CallSite, AVal, Path)}
     */
    public List<Reached> createdBy(CallSite at, Path path) {
        return at.created() < 0 ? List.of() : related(at, Set.of(at.created()), 0, path);
    }

    /**
     * Returns the calls of the given objects of a call's method and of the objects its parameters
     * are, e.g. of one of the objects a value may be.
     *
     * @param at the call, giving the method
     * @param origins ids of sites of that method creating the objects
     * @param params the method's parameters, as a bit set
     * @param path the path {@code at} was reached by
     * @return the calls, as for {@link #related(CallSite, AVal, Path)}
     */
    public List<Reached> related(CallSite at, Set<Integer> origins, long params, Path path) {
        if (origins.isEmpty() && params == 0) {
            return List.of();
        }
        final Visit v = new Visit();
        v.object(at.method(), origins, params, path, 0);
        final List<CryptoApiCall> local = new ArrayList<>(v.local);
        local.sort((a, b) -> Integer.compare(positions.get(a), positions.get(b)));
        final List<Reached> result = new ArrayList<>();
        for (CryptoApiCall c : local) {
            result.add(new Reached(c, path));
        }
        for (Reached r : v.remote.values()) {
            if (!v.local.contains(r.call())) {
                result.add(r);
            }
        }
        return result;
    }

    /** One resolution: the calls found, and what was visited. */
    private final class Visit {
        /** Calls of the starting method's objects, on the starting path. */
        final Set<CryptoApiCall> local = Collections.newSetFromMap(new IdentityHashMap<>());
        /** Calls found in other methods, or on other paths, in the order found. */
        final Map<CryptoApiCall, Reached> remote = new LinkedHashMap<>();
        final Set<String> visited = new HashSet<>();

        /** The objects of a method, given by origins and parameters, as seen on a path. */
        void object(String method, Set<Integer> origins, long params, Path path, int hops) {
            final Refs refs = expand(receivers.getOrDefault(method, Map.of()), origins, params);
            origins = refs.origins();
            params = refs.params();
            final Analyzer.MethodResult m = methods.get(method);
            for (int o : new java.util.TreeSet<>(origins)) {
                if (!visited.add(method + "#o" + o + "@" + path.frames().size() + ":" + id(path))) {
                    continue;
                }
                final CryptoObject obj = objects.getOrDefault(method, Map.of()).get(o);
                if (obj != null) {
                    add(obj.creations(), path, hops);
                    add(obj.events(), path, hops);
                }
                if (m == null || hops >= MAX_HOPS) {
                    continue;
                }
                // passed to callees
                for (CallSite cs : m.calls()) {
                    final Analyzer.MethodResult callee = methods.get(signature(cs));
                    if (callee == null) {
                        continue;
                    }
                    for (int k = 0; k < cs.args().length; k++) {
                        if (cs.args()[k].origins().contains(o)) {
                            parameter(callee.method(), k, path.enter(cs), hops + 1);
                        }
                    }
                }
                // returned to callers
                if (m.returned().origins().contains(o)) {
                    returnedBy(method, path, hops + 1);
                }
            }
            if (m != null && hops < MAX_HOPS) {
                for (int p : bits(params)) {
                    argumentOf(method, p, path, hops + 1);
                }
            }
        }

        /** A method's parameter, as seen on a path ending with the call into it. */
        void parameter(String method, int k, Path path, int hops) {
            if (!visited.add(method + "#p" + k + ":" + id(path))) {
                return;
            }
            add(parameterEvents.getOrDefault(method, Map.of()).getOrDefault(k, List.of()), path, hops);
            final Analyzer.MethodResult m = methods.get(method);
            if (m == null || hops >= MAX_HOPS) {
                return;
            }
            // passed on to further callees
            for (CallSite cs : m.calls()) {
                final Analyzer.MethodResult callee = methods.get(signature(cs));
                if (callee == null) {
                    continue;
                }
                for (int j = 0; j < cs.args().length; j++) {
                    if ((cs.args()[j].params() & (1L << k)) != 0) {
                        parameter(callee.method(), j, path.enter(cs), hops + 1);
                    }
                }
            }
            // returned unchanged: the caller receives the same object
            if ((m.returned().params() & (1L << k)) != 0) {
                returnedBy(method, path, hops + 1);
            }
        }

        /** The object a method returns, received by its caller on the path, or by all callers. */
        void returnedBy(String method, Path path, int hops) {
            if (!path.isRoot()) {
                final CallSite x = path.top();
                if (x.created() >= 0) {
                    object(x.method(), Set.of(x.created()), 0, path.leave(), hops);
                }
                return;
            }
            for (CallSite x : callers.getOrDefault(method, List.of())) {
                if (x.created() >= 0) {
                    object(x.method(), Set.of(x.created()), 0, Path.ROOT, hops);
                }
            }
        }

        /**
         * The argument a method's parameter is, from the caller on the path. At the root there is
         * no caller to take it from: each caller passing an object is a root of its own, entering
         * this method on its path, and merging all callers' objects into one event would lose
         * which caller passed which.
         */
        void argumentOf(String method, int p, Path path, int hops) {
            if (path.isRoot()) {
                return;
            }
            final CallSite x = path.top();
            if (p < x.args().length) {
                object(x.method(), x.args()[p].origins(), x.args()[p].params(), path.leave(), hops);
            }
        }

        private void add(List<CryptoApiCall> found, Path path, int hops) {
            for (CryptoApiCall c : found) {
                if (hops == 0) {
                    local.add(c);
                } else {
                    remote.putIfAbsent(c, new Reached(c, path));
                }
            }
        }
    }

    private static String id(Path path) {
        final StringBuilder sb = new StringBuilder();
        for (CallSite cs : path.frames()) {
            sb.append(cs.id()).append('/');
        }
        return sb.toString();
    }

    private static String signature(CallSite cs) {
        return cs.owner() + "." + cs.name() + cs.descriptor();
    }

    private static List<Integer> bits(long mask) {
        final List<Integer> result = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            if ((mask & (1L << i)) != 0) {
                result.add(i);
            }
        }
        return result;
    }
}
