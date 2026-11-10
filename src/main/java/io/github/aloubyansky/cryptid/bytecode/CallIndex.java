package io.github.aloubyansky.cryptid.bytecode;

import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Index of the calls into the analyzed classes of all artifacts, for resolving values passed into
 * a method from its callers, within an artifact and across artifacts.
 *
 * <p>It records, for every call to a method of an analyzed class, the constants and parameter
 * provenance of its {@code String} and {@code int} arguments, the types whose values the detection
 * rules turn into algorithm names and sizes. When a crypto API argument comes from a parameter of
 * the enclosing method, {@link #resolve} walks up the callers: a caller passing a constant yields
 * that constant, located at the caller's call site; a caller passing its own parameter is followed
 * further up. This is what sonar-cryptography's hooks did within one scan.
 *
 * <p>Calls are matched by the method they invoke, resolved to its declaring class along the
 * superclass chain, then the interfaces for default methods. Calls through a supertype reach its
 * overrides: resolving {@code C.m} also takes the calls to {@code T.m} for every supertype {@code
 * T} of {@code C} declaring {@code m}, interfaces included. This over-approximates, since such a
 * call may dispatch to another implementation.
 *
 * <p>Thread-safe while filling ({@link #addClasses}, {@link #addCalls}); call {@link #finish} once
 * before {@link #resolve}.
 */
public final class CallIndex {

    /** Hops followed up the callers; deeper chains are rare and their cost grows quickly. */
    private static final int MAX_DEPTH = 6;

    /**
     * A class's supertypes and declared methods.
     *
     * @param superclass internal name of the superclass, {@code null} for {@code java.lang.Object}
     * @param interfaces internal names of the directly implemented interfaces
     * @param methods declared methods as {@code name + descriptor}
     */
    public record ClassInfo(String superclass, List<String> interfaces, Set<String> methods) {}

    /**
     * An argument as seen at a call site.
     *
     * @param consts the constants it may be
     * @param params the caller's parameters it may be passed through from
     * @param stored parameters of other methods it may be passed through from, by way of a field
     */
    record Arg(Set<Object> consts, long params, Set<AVal.StoredParam> stored) {}

    /**
     * A call into an analyzed class.
     *
     * @param callerMethod the calling method, {@code owner.name+descriptor}
     * @param file the caller's source file, prefixed with its artifact path
     * @param line the call's line
     * @param signature the invoked method in sonar-java's format
     * @param name the invoked method's name
     * @param args per parameter position: the argument, or {@code null} if not tracked
     */
    public record Site(String callerMethod, String file, int line, String signature, String name, Arg[] args) {}

    /**
     * A value resolved from a caller.
     *
     * @param value the constant
     * @param site the call site passing it
     */
    public record Hit(Object value, Site site) {}

    private static final Comparator<Site> SITE_ORDER = Comparator.comparing(Site::file)
            .thenComparingInt(Site::line)
            .thenComparing(Site::callerMethod)
            .thenComparing(Site::signature);

    private final Set<String> analyzedClasses;
    private final Map<String, ClassInfo> classes = new ConcurrentHashMap<>();
    private final Map<String, List<Site>> byInvoked = new ConcurrentHashMap<>();
    private Map<String, List<Site>> byDeclaring;

    /**
     * Creates an empty index.
     *
     * @param analyzedClasses internal names of all classes of all artifacts; only calls to these
     *     are indexed
     */
    public CallIndex(Set<String> analyzedClasses) {
        this.analyzedClasses = analyzedClasses;
    }

    /**
     * Records the classes of an artifact.
     *
     * @param infos class infos by internal name
     */
    public void addClasses(Map<String, ClassInfo> infos) {
        infos.forEach(classes::putIfAbsent);
    }

    /**
     * Records the calls of an artifact's methods into analyzed classes whose {@code String} or
     * {@code int} arguments carry constants or parameter provenance.
     *
     * @param methods the artifact's methods with their call sites
     * @param locationPrefix the artifact path, prepended to source files
     */
    public void addCalls(List<Analyzer.MethodResult> methods, String locationPrefix) {
        final String prefix = locationPrefix.isEmpty() ? "" : locationPrefix + "/";
        final Map<String, List<Site>> local = new HashMap<>();
        for (Analyzer.MethodResult m : methods) {
            for (CallSite cs : m.calls()) {
                if (!analyzedClasses.contains(cs.owner)) {
                    continue;
                }
                final List<ClassDesc> types = MethodTypeDesc.ofDescriptor(cs.descriptor).parameterList();
                Arg[] args = null;
                for (int p = 0; p < cs.args.length && p < types.size(); p++) {
                    final AVal a = cs.args[p];
                    if (!isResolvableType(types.get(p)) || (a.consts().isEmpty() && a.params() == 0 && a.stored().isEmpty())) {
                        continue;
                    }
                    if (args == null) {
                        args = new Arg[cs.args.length];
                    }
                    args[p] = new Arg(a.consts(), a.params(), a.stored());
                }
                if (args != null) {
                    local.computeIfAbsent(cs.owner + "." + cs.name + cs.descriptor, k -> new ArrayList<>())
                            .add(new Site(m.method(), prefix + m.sourceFile(), cs.line, cs.signature(), cs.name, args));
                }
            }
        }
        // ConcurrentHashMap.merge is atomic per key
        local.forEach((key, sites) -> byInvoked.merge(key, sites, (a, b) -> {
            final List<Site> all = new ArrayList<>(a);
            all.addAll(b);
            return all;
        }));
    }

    /**
     * Whether arguments of a type are indexed: {@code String} and {@code int}, the values specs
     * turn into names and sizes.
     *
     * @param type the parameter type
     * @return {@code true} for {@code String} and {@code int}
     */
    static boolean isResolvableType(ClassDesc type) {
        final String d = type.descriptorString();
        return d.equals("Ljava/lang/String;") || d.equals("I");
    }

    /**
     * Groups the recorded calls by the method they reach, resolving each invoked method to its
     * declaring class along the superclass chain.
     */
    public void finish() {
        final Map<String, List<Site>> result = new HashMap<>();
        byInvoked.forEach((key, sites) -> result.computeIfAbsent(declaring(key), k -> new ArrayList<>()).addAll(sites));
        // artifacts are indexed in parallel: order the sites, so values resolve in the same order in every run
        result.values().forEach(sites -> sites.sort(SITE_ORDER));
        byDeclaring = result;
    }

    private String declaring(String key) {
        final int dot = key.indexOf('.');
        final String owner = key.substring(0, dot);
        final String member = key.substring(dot + 1);
        // the superclass chain first, as the JVM resolves methods
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
        // then default methods of the interfaces
        for (String t : supertypes(owner)) {
            final ClassInfo ci = classes.get(t);
            if (ci != null && ci.methods().contains(member)) {
                return t + "." + member;
            }
        }
        return key;
    }

    private final Map<String, List<String>> supertypes = new ConcurrentHashMap<>();

    /**
     * Returns the analyzed supertypes of a class, superclasses and interfaces, transitively,
     * nearest first.
     *
     * @param owner the class's internal name
     * @return the supertypes, without the class itself
     */
    private List<String> supertypes(String owner) {
        return supertypes.computeIfAbsent(owner, o -> {
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

    /**
     * Returns the methods whose calls may dispatch to a method: itself, and the same method
     * declared in any of its class's supertypes.
     *
     * @param method {@code owner.name+descriptor}
     * @return method keys
     */
    private List<String> dispatchSources(String method) {
        final int dot = method.indexOf('.');
        final String owner = method.substring(0, dot);
        final String member = method.substring(dot + 1);
        final List<String> result = new ArrayList<>(List.of(method));
        if (member.startsWith("<init>") || member.startsWith("<clinit>")) {
            return result;
        }
        for (String t : supertypes(owner)) {
            final ClassInfo ci = classes.get(t);
            if (ci != null && ci.methods().contains(member)) {
                result.add(t + "." + member);
            }
        }
        return result;
    }

    /**
     * Resolves the values of a method's parameters from its callers.
     *
     * @param method the method, {@code owner.name+descriptor}
     * @param params the parameters to resolve, one bit per parameter index
     * @return the constants passed by callers, each with the call site passing it; empty if none
     */
    public List<Hit> resolve(String method, long params) {
        final List<Hit> hits = new ArrayList<>();
        resolve(method, params, 0, new HashSet<>(), hits);
        return hits;
    }

    private void resolve(String method, long params, int depth, Set<String> visited, List<Hit> hits) {
        if (depth >= MAX_DEPTH || !visited.add(method + "#" + params)) {
            return;
        }
        final List<Site> sites = new ArrayList<>();
        for (String source : dispatchSources(method)) {
            sites.addAll(byDeclaring.getOrDefault(source, List.of()));
        }
        for (Site site : sites) {
            long callerParams = 0;
            for (int p = 0; p < site.args().length && p < AVal.MAX_PARAMS; p++) {
                final Arg a = site.args()[p];
                if (a == null || (params & (1L << p)) == 0) {
                    continue;
                }
                for (Object c : a.consts()) {
                    hits.add(new Hit(c, site));
                }
                callerParams |= a.params();
                // a field the caller passes on: from the callers of the method that stored it
                for (AVal.StoredParam sp : a.stored()) {
                    resolve(sp.method(), 1L << sp.index(), depth + 1, visited, hits);
                }
            }
            if (callerParams != 0) {
                resolve(site.callerMethod(), callerParams, depth + 1, visited, hits);
            }
        }
    }

    /**
     * Returns the number of indexed call sites, for logging.
     *
     * @return the number of call sites
     */
    public int size() {
        return byInvoked.values().stream().mapToInt(List::size).sum();
    }
}
