package io.github.aloubyansky.cryptid.bytecode;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Resolving the values of a method's parameters from its callers: the call sites passing them,
 * and the walk up the callers. When a crypto API argument comes from a parameter of the enclosing
 * method, a caller passing a constant yields that constant, located at the caller's call site; a
 * caller passing its own parameter, or a field stored from one, is followed further up. This is
 * what sonar-cryptography's hooks did within one scan.
 *
 * <p>Calls are matched by the method they invoke, resolved to its declaring class. Calls through a
 * supertype reach its overrides: resolving {@code C.m} also takes the calls to {@code T.m} for
 * every supertype {@code T} of {@code C} declaring {@code m}, interfaces included. This
 * over-approximates, since such a call may dispatch to another implementation.
 *
 * <p>Where the call sites come from is up to the {@link CallResolver}: {@link DemandCallIndex}
 * finds them through the call graph.
 */
public final class Callers {

    /** Hops followed up the callers; deeper chains are rare and their cost grows quickly. */
    static final int MAX_DEPTH = 6;

    private Callers() {}

    /**
     * An argument as seen at a call site.
     *
     * @param consts the constants it may be
     * @param params the caller's parameters it may be passed through from
     * @param stored parameters of other methods it may be passed through from, by way of a field
     */
    public record Arg(Set<Object> consts, long params, Set<AVal.StoredParam> stored) {}

    /**
     * A call into an analyzed class.
     *
     * @param callerMethod the calling method, {@code owner.name+descriptor}
     * @param artifact the caller's artifact, or {@code null} if not known
     * @param sourceFile the caller's source file, without the artifact path
     * @param file the caller's source file, prefixed with its artifact path
     * @param line the call's line
     * @param signature the invoked method in sonar-java's format
     * @param name the invoked method's name
     * @param args per parameter position: the argument, or {@code null} if not tracked
     */
    public record Site(String callerMethod, ArtifactCoordinates artifact, String sourceFile, String file, int line, String signature, String name, Arg[] args) {}

    /**
     * A value resolved from a caller.
     *
     * @param value the constant
     * @param site the call site passing it
     */
    public record Hit(Object value, Site site) {}

    /** The order call sites are resolved in, independent of the order they were found in. */
    static final Comparator<Site> SITE_ORDER = Comparator.comparing(Site::file)
            .thenComparingInt(Site::line)
            .thenComparing(Site::callerMethod)
            .thenComparing(Site::signature);

    /**
     * The site of a call, with its {@code String} and {@code int} arguments that carry constants
     * or parameter provenance.
     *
     * @param m the calling method
     * @param cs the call
     * @param artifact the caller's artifact, or {@code null} if not known
     * @param prefix the artifact path followed by {@code /}, or empty
     * @return the site, or {@code null} if no argument carries anything to resolve
     */
    static Site site(Analyzer.MethodResult m, CallSite cs, ArtifactCoordinates artifact, String prefix) {
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
        return args == null ? null
                : new Site(m.method(), artifact, m.sourceFile(), prefix + m.sourceFile(), cs.line, cs.signature(), cs.name, args);
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
     * Returns the methods whose calls may dispatch to a method: itself, and the same method
     * declared in any of its class's supertypes.
     *
     * @param method {@code owner.name+descriptor}
     * @return method keys
     */
    static List<String> dispatchSources(Hierarchy hierarchy, String method) {
        final int dot = method.indexOf('.');
        final String owner = method.substring(0, dot);
        final String member = method.substring(dot + 1);
        final List<String> result = new ArrayList<>(List.of(method));
        if (member.startsWith("<init>") || member.startsWith("<clinit>")) {
            return result;
        }
        for (String t : hierarchy.supertypes(owner)) {
            final ClassInfo ci = hierarchy.get(t);
            if (ci != null && ci.methods().contains(member)) {
                result.add(t + "." + member);
            }
        }
        return result;
    }

    /**
     * Resolves the values of a method's parameters from its callers, given the call sites
     * reaching each method.
     *
     * @param hierarchy the class table, for the methods a call may dispatch to
     * @param sitesOf the call sites reaching a method, by its declaring key, in {@link #SITE_ORDER}
     * @param method the method, {@code owner.name+descriptor}
     * @param params the parameters to resolve, one bit per parameter index
     * @return the constants passed by callers, each with the call site passing it
     */
    static List<Hit> resolve(Hierarchy hierarchy, Function<String, List<Site>> sitesOf, String method,
            long params) {
        final List<Hit> hits = new ArrayList<>();
        resolve(hierarchy, sitesOf, method, params, 0, new HashSet<>(), hits);
        return hits;
    }

    private static void resolve(Hierarchy hierarchy, Function<String, List<Site>> sitesOf, String method,
            long params, int depth, Set<String> visited, List<Hit> hits) {
        if (depth >= MAX_DEPTH || !visited.add(method + "#" + params)) {
            return;
        }
        final List<Site> sites = new ArrayList<>();
        for (String source : dispatchSources(hierarchy, method)) {
            sites.addAll(sitesOf.apply(source));
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
                    resolve(hierarchy, sitesOf, sp.method(), 1L << sp.index(), depth + 1, visited, hits);
                }
            }
            if (callerParams != 0) {
                resolve(hierarchy, sitesOf, site.callerMethod(), callerParams, depth + 1, visited, hits);
            }
        }
    }
}
